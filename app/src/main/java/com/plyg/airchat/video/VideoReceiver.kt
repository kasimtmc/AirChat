package com.plyg.airchat.video

import android.media.MediaCodec
import android.media.MediaFormat
import android.os.Build
import android.os.Handler
import android.os.HandlerThread
import android.os.SystemClock
import android.util.Log
import android.view.Surface
import com.plyg.airchat.BuildConfig
import com.plyg.airchat.net.VideoFrame

/** How the contact's picture comes: its size as encoded, and the quarter turns that show it upright. */
data class VideoFormat(val width: Int, val height: Int, val rotation: Int)

/**
 * The contact's video in a call (docs/architecture.md §6): frames from the core into the hardware
 * H.264 decoder, which draws them on a surface. Frames stay in memory and are wiped once handed
 * over. Without a surface, or before a key frame, frames are dropped and a key frame is asked for.
 * Everything runs on one thread of its own.
 */
class VideoReceiver(
    /** The decoder cannot go on without a key frame. At most once a second; on the video thread. */
    private val onNeedKeyFrame: () -> Unit,
    /** The picture's size or rotation changed; on the video thread. */
    private val onFormat: (VideoFormat) -> Unit,
) {
    private val thread = HandlerThread("AirChat video").apply { start() }
    private val handler = Handler(thread.looper)

    private var surface: Surface? = null
    private var codec: MediaCodec? = null
    private var codecSize: Pair<Int, Int>? = null
    private var format: VideoFormat? = null
    private val pending = ArrayDeque<VideoFrame>()
    private val freeInputs = ArrayDeque<Int>()
    private var awaitingKey = true
    private var askedAt = 0L
    private var presentationUs = 0L
    private var closed = false

    /**
     * Where to draw, or null while the picture is not shown. [releaseOld] runs once the decoder no
     * longer draws into the previous surface.
     */
    fun setSurface(surface: Surface?, releaseOld: () -> Unit = {}) = handler.post {
        stopCodec()
        releaseOld()
        this.surface = surface
        format = null
        if (surface != null && !closed) needKeyFrame()
    }

    /** A frame from the core; any thread. */
    fun push(frame: VideoFrame) {
        if (!handler.post { decode(frame) }) frame.data.fill(0)
    }

    /** Stops drawing; the surface stays its owner's. */
    fun close() = handler.post {
        closed = true
        stopCodec()
        surface = null
        thread.quitSafely()
    }

    // On the video thread.

    private fun decode(frame: VideoFrame) {
        val surface = surface
        if (surface == null || closed) return frame.data.fill(0)
        if (!frame.key && awaitingKey) {
            needKeyFrame()
            return frame.data.fill(0)
        }
        if (codec == null || codecSize != frame.width to frame.height) {
            if (!frame.key) {
                awaitingKey = true
                needKeyFrame()
                return frame.data.fill(0)
            }
            stopCodec()
            startCodec(surface, frame.width, frame.height) ?: return frame.data.fill(0)
        }
        if (frame.key) awaitingKey = false
        VideoFormat(frame.width, frame.height, frame.rotation).takeIf { it != format }?.let {
            format = it
            onFormat(it)
        }
        pending.addLast(frame)
        if (pending.size > MAX_PENDING) {
            // The decoder falls behind: start over from a key frame rather than show it late.
            dropPending()
            awaitingKey = true
            needKeyFrame()
            return
        }
        feed()
    }

    private fun startCodec(surface: Surface, width: Int, height: Int): MediaCodec? {
        val codec = try {
            MediaCodec.createDecoderByType(MediaFormat.MIMETYPE_VIDEO_AVC)
        } catch (e: Exception) {
            debug("no H.264 decoder: $e")
            return null
        }
        val format = MediaFormat.createVideoFormat(MediaFormat.MIMETYPE_VIDEO_AVC, width, height).apply {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) setInteger(MediaFormat.KEY_LOW_LATENCY, 1)
            setInteger(MediaFormat.KEY_PRIORITY, 0)
        }
        return try {
            codec.setCallback(callback, handler)
            codec.configure(format, surface, null, 0)
            codec.start()
            this.codec = codec
            codecSize = width to height
            freeInputs.clear()
            codec
        } catch (e: Exception) {
            debug("could not start the decoder: $e")
            codec.release()
            null
        }
    }

    private fun feed() {
        val codec = codec ?: return
        while (pending.isNotEmpty() && freeInputs.isNotEmpty()) {
            val index = freeInputs.removeFirst()
            val frame = pending.removeFirst()
            try {
                val buffer = codec.getInputBuffer(index) ?: continue
                if (buffer.capacity() < frame.data.size) {
                    debug("frame larger than the decoder's buffer")
                    awaitingKey = true
                    needKeyFrame()
                    codec.queueInputBuffer(index, 0, 0, presentationUs, 0)
                    continue
                }
                buffer.clear()
                buffer.put(frame.data)
                presentationUs += FRAME_US
                codec.queueInputBuffer(index, 0, frame.data.size, presentationUs, 0)
            } catch (e: IllegalStateException) {
                debug("decoder input failed: $e")
            } finally {
                frame.data.fill(0)
            }
        }
    }

    private val callback = object : MediaCodec.Callback() {
        override fun onInputBufferAvailable(codec: MediaCodec, index: Int) {
            if (codec !== this@VideoReceiver.codec) return
            freeInputs.addLast(index)
            feed()
        }

        override fun onOutputBufferAvailable(codec: MediaCodec, index: Int, info: MediaCodec.BufferInfo) {
            if (codec !== this@VideoReceiver.codec) return
            try {
                codec.releaseOutputBuffer(index, info.size > 0)
            } catch (_: IllegalStateException) {
            }
        }

        override fun onError(codec: MediaCodec, e: MediaCodec.CodecException) {
            if (codec !== this@VideoReceiver.codec) return
            debug("decoder error: $e")
            stopCodec()
            awaitingKey = true
            needKeyFrame()
        }

        override fun onOutputFormatChanged(codec: MediaCodec, format: MediaFormat) = Unit
    }

    private fun needKeyFrame() {
        val now = SystemClock.elapsedRealtime()
        if (now - askedAt < KEY_FRAME_ASK_MS) return
        askedAt = now
        onNeedKeyFrame()
    }

    private fun dropPending() {
        pending.forEach { it.data.fill(0) }
        pending.clear()
    }

    private fun stopCodec() {
        dropPending()
        freeInputs.clear()
        codec?.let {
            try {
                it.stop()
            } catch (_: IllegalStateException) {
            }
            it.release()
        }
        codec = null
        codecSize = null
        awaitingKey = true
    }

    private fun debug(message: String) {
        if (BuildConfig.DEBUG) Log.d(TAG, message)
    }

    private companion object {
        const val TAG = "AirChat"
        /** Frames waiting for the decoder; more means it cannot keep up. */
        const val MAX_PENDING = 8
        const val KEY_FRAME_ASK_MS = 1_000L
        const val FRAME_US = 33_333L
    }
}
