package com.plyg.airchat.audio

import android.annotation.SuppressLint
import android.content.Context
import android.media.AudioAttributes
import android.media.AudioDeviceCallback
import android.media.AudioDeviceInfo
import android.media.AudioFocusRequest
import android.media.AudioFormat
import android.media.AudioManager
import android.media.AudioRecord
import android.media.AudioTrack
import android.media.MediaCodec
import android.media.MediaCodecInfo
import android.media.MediaFormat
import android.media.MediaRecorder
import android.media.audiofx.AcousticEchoCanceler
import android.media.audiofx.NoiseSuppressor
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.os.SystemClock
import android.util.Log
import com.plyg.airchat.BuildConfig
import com.plyg.airchat.core.JitterBuffer
import com.plyg.airchat.core.Playout
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.concurrent.ConcurrentHashMap
import kotlin.concurrent.thread

/** Wideband speech: the rate voice is captured and encoded at (voice messages say so too). */
const val VOICE_RATE = 16_000

/**
 * Voice for one call or talk (docs/architecture.md §6): microphone → Opus → [onPacket], and
 * packets → jitter buffer → Opus → speaker, one buffer and decoder per sender, mixed (a group call
 * has several). Audio stays in memory: PCM and packets pass straight between the microphone, the
 * codecs, the core and the speaker, and buffers are wiped after use.
 *
 * Opus runs on the platform's codec (Android 10+), at a constant bitrate, so packet sizes say
 * nothing about the speech.
 */
class VoiceEngine(context: Context, private val onPacket: (ByteArray) -> Unit) {
    private val audio = context.getSystemService(AudioManager::class.java)
    @Volatile private var sending = false
    @Volatile private var playing = false
    /** Each sender's packets, by contact; filled from any thread, emptied by the playback thread. */
    private val sources = ConcurrentHashMap<Long, JitterBuffer>()
    private var captureThread: Thread? = null
    private var playbackThread: Thread? = null
    private var focus: AudioFocusRequest? = null

    /** Captured audio is dropped instead of sent. */
    @Volatile var muted = false

    /** Captured audio is dropped until then ([SystemClock.elapsedRealtime]), e.g. while the chirp plays. */
    @Volatile private var quietUntil = 0L

    /** Without a choice: a headset if one is connected, else the loudspeaker (push-to-talk) or the earpiece (calls). */
    private var loudByDefault = false

    /** The user's choice on the call screen: loudspeaker or not; null leaves it to [route]. */
    var speaker: Boolean? = null
        set(value) {
            field = value
            route()
        }

    /** Re-routes when a headset comes or goes during a call or talk. */
    private val devices = object : AudioDeviceCallback() {
        override fun onAudioDevicesAdded(added: Array<out AudioDeviceInfo>) = route()

        override fun onAudioDevicesRemoved(removed: Array<out AudioDeviceInfo>) = route()
    }

    /**
     * Takes the audio route for voice; call before starting to send or play. A connected headset
     * always wins over [loud] (the loudspeaker rather than the earpiece).
     */
    fun open(loud: Boolean) {
        loudByDefault = loud
        audio.mode = AudioManager.MODE_IN_COMMUNICATION
        val attributes = AudioAttributes.Builder()
            .setUsage(AudioAttributes.USAGE_VOICE_COMMUNICATION)
            .setContentType(AudioAttributes.CONTENT_TYPE_SPEECH)
            .build()
        focus = AudioFocusRequest.Builder(AudioManager.AUDIOFOCUS_GAIN_TRANSIENT).setAudioAttributes(attributes).build()
            .also(audio::requestAudioFocus)
        audio.registerAudioDeviceCallback(devices, Handler(Looper.getMainLooper()))
        route()
    }

    /** The walkie-talkie sound for the talker, out of whatever voice plays on; the microphone
     * ignores it. */
    fun playChirp() {
        quietUntil = SystemClock.elapsedRealtime() + Chirp.DURATION_MS + CHIRP_TAIL_MS
        val pcm = Chirp.pcm(PLAY_RATE)
        val track = AudioTrack.Builder()
            .setAudioAttributes(voiceAttributes())
            .setAudioFormat(playFormat())
            .setBufferSizeInBytes(pcm.size)
            .setTransferMode(AudioTrack.MODE_STATIC)
            .build()
        track.write(pcm, 0, pcm.size)
        track.play()
        Handler(Looper.getMainLooper()).postDelayed({ track.release() }, Chirp.DURATION_MS + CHIRP_TAIL_MS)
    }

    @SuppressLint("MissingPermission") // The caller checks RECORD_AUDIO first.
    fun startSending() {
        if (sending) return
        sending = true
        captureThread = thread(name = "AirChat voice capture", priority = Thread.MAX_PRIORITY) {
            try {
                capture()
            } catch (e: Exception) {
                if (BuildConfig.DEBUG) Log.w(TAG, "voice capture stopped", e)
            }
        }
    }

    /** The capture thread stops within a frame and releases what it holds. */
    fun stopSending() {
        sending = false
        captureThread = null
    }

    /** Plays the packets [push]ed from now on; after the walkie-talkie sound with [chirp]. */
    fun startPlaying(chirp: Boolean = false) {
        if (playing) return
        sources.clear()
        playing = true
        playbackThread = thread(name = "AirChat voice playback", priority = Thread.MAX_PRIORITY) {
            try {
                playback(chirp)
            } catch (e: Exception) {
                if (BuildConfig.DEBUG) Log.w(TAG, "voice playback stopped", e)
            }
        }
    }

    fun stopPlaying() {
        playing = false
        playbackThread = null
        sources.clear()
    }

    /** A packet from contact [from]; any thread. */
    fun push(from: Long, seq: UInt, packet: ByteArray) {
        if (playing) sources.computeIfAbsent(from) { JitterBuffer(JITTER_TARGET, JITTER_MAX) }.push(seq, packet)
        packet.fill(0)
    }

    /** Stops everything and gives the audio route back; quick, the threads finish on their own. */
    fun close() {
        stopSending()
        stopPlaying()
        audio.unregisterAudioDeviceCallback(devices)
        if (Build.VERSION.SDK_INT >= 31) audio.clearCommunicationDevice() else @Suppress("DEPRECATION") run {
            audio.isSpeakerphoneOn = false
        }
        focus?.let(audio::abandonAudioFocusRequest)
        focus = null
        audio.mode = AudioManager.MODE_NORMAL
    }

    /** Loudspeaker if chosen; otherwise a headset if connected, else the default for the use. */
    private fun route() {
        val loud = speaker ?: loudByDefault
        if (Build.VERSION.SDK_INT >= 31) {
            val available = audio.availableCommunicationDevices
            val headset = available.firstOrNull { it.type in HEADSETS }
            val device = when {
                speaker == true -> available.firstOrNull { it.type == AudioDeviceInfo.TYPE_BUILTIN_SPEAKER }
                headset != null -> headset
                loud -> available.firstOrNull { it.type == AudioDeviceInfo.TYPE_BUILTIN_SPEAKER }
                else -> available.firstOrNull { it.type == AudioDeviceInfo.TYPE_BUILTIN_EARPIECE }
            }
            device?.let(audio::setCommunicationDevice)
        } else {
            // Android 10 and 11: a wired headset takes over by itself unless the loudspeaker is on;
            // a Bluetooth one needs its voice link (SCO).
            val outputs = audio.getDevices(AudioManager.GET_DEVICES_OUTPUTS)
            val wired = outputs.any { it.type in WIRED }
            val bluetooth = outputs.any { it.type == AudioDeviceInfo.TYPE_BLUETOOTH_SCO }
            val useBluetooth = bluetooth && !wired && speaker != true
            @Suppress("DEPRECATION")
            run {
                if (useBluetooth) audio.startBluetoothSco() else audio.stopBluetoothSco()
                audio.isBluetoothScoOn = useBluetooth
                audio.isSpeakerphoneOn = speaker == true || (loud && !wired && !useBluetooth)
            }
        }
    }

    private fun voiceAttributes() = AudioAttributes.Builder()
        .setUsage(AudioAttributes.USAGE_VOICE_COMMUNICATION)
        .setContentType(AudioAttributes.CONTENT_TYPE_SPEECH)
        .build()

    private fun playFormat() = AudioFormat.Builder()
        .setSampleRate(PLAY_RATE)
        .setChannelMask(AudioFormat.CHANNEL_OUT_MONO)
        .setEncoding(AudioFormat.ENCODING_PCM_16BIT)
        .build()

    @SuppressLint("MissingPermission")
    private fun capture() {
        val minimum = AudioRecord.getMinBufferSize(RATE, AudioFormat.CHANNEL_IN_MONO, AudioFormat.ENCODING_PCM_16BIT)
        val record = AudioRecord.Builder()
            .setAudioSource(MediaRecorder.AudioSource.VOICE_COMMUNICATION)
            .setAudioFormat(
                AudioFormat.Builder()
                    .setSampleRate(RATE)
                    .setChannelMask(AudioFormat.CHANNEL_IN_MONO)
                    .setEncoding(AudioFormat.ENCODING_PCM_16BIT)
                    .build(),
            )
            .setBufferSizeInBytes(maxOf(minimum, FRAME_BYTES * 4))
            .build()
        val effects = listOfNotNull(
            AcousticEchoCanceler.create(record.audioSessionId)?.takeIf { AcousticEchoCanceler.isAvailable() },
            NoiseSuppressor.create(record.audioSessionId)?.takeIf { NoiseSuppressor.isAvailable() },
        ).onEach { it.enabled = true }
        val encoder = MediaCodec.createEncoderByType(MediaFormat.MIMETYPE_AUDIO_OPUS)
        val format = MediaFormat.createAudioFormat(MediaFormat.MIMETYPE_AUDIO_OPUS, RATE, 1).apply {
            setInteger(MediaFormat.KEY_BIT_RATE, BITRATE)
            setInteger(MediaFormat.KEY_MAX_INPUT_SIZE, FRAME_BYTES)
            val capabilities = encoder.codecInfo.getCapabilitiesForType(MediaFormat.MIMETYPE_AUDIO_OPUS).encoderCapabilities
            if (capabilities?.isBitrateModeSupported(MediaCodecInfo.EncoderCapabilities.BITRATE_MODE_CBR) == true) {
                setInteger(MediaFormat.KEY_BITRATE_MODE, MediaCodecInfo.EncoderCapabilities.BITRATE_MODE_CBR)
            }
        }
        encoder.configure(format, null, null, MediaCodec.CONFIGURE_FLAG_ENCODE)
        encoder.start()
        val pcm = ByteArray(FRAME_BYTES)
        val info = MediaCodec.BufferInfo()
        var timeUs = 0L
        try {
            record.startRecording()
            while (sending) {
                var read = 0
                while (read < pcm.size && sending) {
                    val n = record.read(pcm, read, pcm.size - read)
                    if (n <= 0) break
                    read += n
                }
                if (read < pcm.size) break
                val input = encoder.dequeueInputBuffer(CODEC_WAIT_US)
                if (input >= 0) {
                    encoder.getInputBuffer(input)?.apply {
                        clear()
                        put(pcm)
                    }
                    encoder.queueInputBuffer(input, 0, pcm.size, timeUs, 0)
                    timeUs += FRAME_US
                }
                while (true) {
                    val output = encoder.dequeueOutputBuffer(info, 0)
                    if (output < 0) break
                    val config = info.flags and MediaCodec.BUFFER_FLAG_CODEC_CONFIG != 0
                    val quiet = SystemClock.elapsedRealtime() < quietUntil
                    if (!config && info.size > 0 && !muted && !quiet) {
                        val packet = ByteArray(info.size)
                        encoder.getOutputBuffer(output)?.apply {
                            position(info.offset)
                            get(packet)
                        }
                        onPacket(packet)
                        packet.fill(0)
                    }
                    encoder.releaseOutputBuffer(output, false)
                }
            }
        } finally {
            pcm.fill(0)
            runCatching { record.stop() }
            record.release()
            effects.forEach { it.release() }
            runCatching { encoder.stop() }
            encoder.release()
        }
    }

    private fun newDecoder(): MediaCodec {
        val decoder = MediaCodec.createDecoderByType(MediaFormat.MIMETYPE_AUDIO_OPUS)
        val format = MediaFormat.createAudioFormat(MediaFormat.MIMETYPE_AUDIO_OPUS, PLAY_RATE, 1).apply {
            setByteBuffer("csd-0", opusHead())
            setByteBuffer("csd-1", littleEndianLong(0))
            setByteBuffer("csd-2", littleEndianLong(SEEK_PREROLL_NS))
        }
        decoder.configure(format, null, null, 0)
        decoder.start()
        return decoder
    }

    private fun playback(chirp: Boolean) {
        val decoders = HashMap<Long, MediaCodec>()
        val track = AudioTrack.Builder()
            .setAudioAttributes(voiceAttributes())
            .setAudioFormat(playFormat())
            .setBufferSizeInBytes(
                maxOf(
                    AudioTrack.getMinBufferSize(PLAY_RATE, AudioFormat.CHANNEL_OUT_MONO, AudioFormat.ENCODING_PCM_16BIT),
                    PLAY_FRAME_BYTES * 3,
                ),
            )
            .setTransferMode(AudioTrack.MODE_STREAM)
            .build()
        val silence = ByteArray(PLAY_FRAME_BYTES)
        val mix = IntArray(PLAY_FRAME_BYTES / 2)
        val out = ByteArray(PLAY_FRAME_BYTES)
        val info = MediaCodec.BufferInfo()
        var timeUs = 0L
        try {
            track.play()
            if (chirp) Chirp.pcm(PLAY_RATE).let { track.write(it, 0, it.size) }
            while (playing) {
                // One frame per round from each sender, added up; the blocking write keeps time
                // with the speaker.
                mix.fill(0)
                var heard = 0
                for ((from, jitter) in sources) {
                    val next = jitter.pop() as? Playout.Packet ?: continue
                    val decoder = decoders.getOrPut(from, ::newDecoder)
                    val decoded = decode(decoder, next.data, timeUs, info)
                    next.data.fill(0)
                    if (decoded == null || decoded.isEmpty()) continue
                    for (i in 0 until minOf(mix.size, decoded.size / 2)) {
                        mix[i] += (decoded[2 * i].toInt() and 0xFF) or (decoded[2 * i + 1].toInt() shl 8)
                    }
                    decoded.fill(0)
                    heard++
                }
                timeUs += FRAME_US
                if (heard == 0) {
                    track.write(silence, 0, silence.size)
                    continue
                }
                for (i in mix.indices) {
                    val sample = mix[i].coerceIn(Short.MIN_VALUE.toInt(), Short.MAX_VALUE.toInt())
                    out[2 * i] = sample.toByte()
                    out[2 * i + 1] = (sample shr 8).toByte()
                }
                track.write(out, 0, out.size)
            }
        } finally {
            mix.fill(0)
            out.fill(0)
            runCatching { track.stop() }
            track.release()
            for (decoder in decoders.values) {
                runCatching { decoder.stop() }
                decoder.release()
            }
        }
    }

    /** One packet through the decoder; whatever PCM it gives within a few milliseconds. */
    private fun decode(decoder: MediaCodec, packet: ByteArray, timeUs: Long, info: MediaCodec.BufferInfo): ByteArray? {
        val input = decoder.dequeueInputBuffer(CODEC_WAIT_US)
        if (input < 0) return null
        decoder.getInputBuffer(input)?.apply {
            clear()
            put(packet)
        }
        decoder.queueInputBuffer(input, 0, packet.size, timeUs, 0)
        val output = decoder.dequeueOutputBuffer(info, CODEC_WAIT_US)
        if (output < 0) return null
        val pcm = ByteArray(info.size)
        decoder.getOutputBuffer(output)?.apply {
            position(info.offset)
            get(pcm)
        }
        decoder.releaseOutputBuffer(output, false)
        return pcm
    }

    private companion object {
        const val TAG = "AirChat"
        /** Wideband speech in; the decoder gives 48 kHz out. */
        const val RATE = VOICE_RATE
        const val PLAY_RATE = 48_000
        const val BITRATE = 24_000
        const val FRAME_US = 20_000L
        const val FRAME_BYTES = RATE / 50 * 2
        const val PLAY_FRAME_BYTES = PLAY_RATE / 50 * 2
        const val CODEC_WAIT_US = 5_000L
        const val SEEK_PREROLL_NS = 80_000_000L
        const val JITTER_TARGET = 3u
        const val JITTER_MAX = 15u
        const val CHIRP_TAIL_MS = 60L

        /** Where voice goes when connected, unless the loudspeaker is chosen. */
        val HEADSETS = setOf(
            AudioDeviceInfo.TYPE_WIRED_HEADSET,
            AudioDeviceInfo.TYPE_WIRED_HEADPHONES,
            AudioDeviceInfo.TYPE_USB_HEADSET,
            AudioDeviceInfo.TYPE_BLUETOOTH_SCO,
            AudioDeviceInfo.TYPE_BLE_HEADSET,
            AudioDeviceInfo.TYPE_HEARING_AID,
        )
        val WIRED = setOf(
            AudioDeviceInfo.TYPE_WIRED_HEADSET,
            AudioDeviceInfo.TYPE_WIRED_HEADPHONES,
            AudioDeviceInfo.TYPE_USB_HEADSET,
        )

        /** The Opus identification header (RFC 7845 §5.1) the platform decoder wants as csd-0. */
        fun opusHead(): ByteBuffer = ByteBuffer.allocate(19).order(ByteOrder.LITTLE_ENDIAN).apply {
            put("OpusHead".toByteArray(Charsets.US_ASCII))
            put(1) // version
            put(1) // channels
            putShort(0) // pre-skip
            putInt(RATE) // original input rate, for information
            putShort(0) // output gain
            put(0) // channel mapping family
            flip()
        }

        fun littleEndianLong(value: Long): ByteBuffer =
            ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN).putLong(value).apply { flip() }
    }
}
