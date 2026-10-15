package com.plyg.airchat.video

import android.annotation.SuppressLint
import android.content.Context
import android.graphics.SurfaceTexture
import android.hardware.camera2.CameraCaptureSession
import android.hardware.camera2.CameraCharacteristics
import android.hardware.camera2.CameraDevice
import android.hardware.camera2.CameraManager
import android.hardware.camera2.CaptureRequest
import android.hardware.camera2.params.OutputConfiguration
import android.hardware.camera2.params.SessionConfiguration
import android.media.MediaCodec
import android.media.MediaCodecInfo
import android.media.MediaFormat
import android.os.Bundle
import android.os.Handler
import android.os.HandlerThread
import android.util.Log
import android.util.Range
import android.util.Size
import android.view.OrientationEventListener
import android.view.Surface
import com.plyg.airchat.BuildConfig
import java.util.concurrent.Executor

/**
 * This device's camera in a video call (docs/architecture.md §6, rust/airchat-protocol/docs/protocol.md §8.6): Camera2 into
 * the hardware H.264 encoder, whose frames go to [onFrame], and into a local preview. Frames stay in
 * memory. Everything runs on one thread of its own; the public calls only post to it.
 */
class CameraSender(
    context: Context,
    /** For a group call: everyone passes every video on, so pictures are smaller (§9.9). */
    private val group: Boolean = false,
    /**
     * An encoded frame, Annex B (a key frame starts with SPS and PPS), and the quarter turns
     * clockwise that show it upright. On the camera thread; the array is the receiver's to wipe.
     */
    private val onFrame: (frame: ByteArray, key: Boolean, rotation: Int, width: Int, height: Int) -> Unit,
    /** The camera stopped by itself: taken by another app, or failed. On the camera thread. */
    private val onStopped: () -> Unit,
) {
    private val manager = context.getSystemService(CameraManager::class.java)
    private val maxWidth = if (group) GROUP_MAX_SIDE else MAX_WIDTH
    private val maxHeight = if (group) GROUP_MAX_SIDE else MAX_HEIGHT
    private val frameRate = if (group) GROUP_FRAME_RATE else FRAME_RATE
    private val thread = HandlerThread("AirChat camera").apply { start() }
    private val handler = Handler(thread.looper)
    private val executor = Executor { handler.post(it) }

    private var front = true
    private var cameraId: String? = null
    private var sensorOrientation = 0
    private var fpsRange: Range<Int>? = null
    private var size = Size(1280, 720)
    private var camera: CameraDevice? = null
    private var session: CameraCaptureSession? = null
    private var encoder: MediaCodec? = null
    private var encoderSurface: Surface? = null
    private var previewTexture: SurfaceTexture? = null
    private var preview: Surface? = null
    /**
     * The encoder's SPS and PPS, put before every key frame that comes without them (asking the
     * encoder to do it, `KEY_PREPEND_HEADER_TO_SYNC_FRAMES`, makes some refuse the format).
     */
    private var codecConfig: ByteArray? = null
    private var sending = false
    private var bitrate = START_BITRATE
    private var closed = false
    /** Old previews to let go once the camera stopped drawing into them. */
    private val toRelease = mutableListOf<() -> Unit>()

    /** How far the device is turned from its natural orientation, clockwise, in degrees. */
    @Volatile private var deviceOrientation = 0
    private val orientation = object : OrientationEventListener(context) {
        override fun onOrientationChanged(degrees: Int) {
            if (degrees != ORIENTATION_UNKNOWN) deviceOrientation = degrees
        }
    }

    /** The size frames are captured and encoded at; known once [open] ran. */
    @Volatile var captureSize: Size = size
        private set

    /** Opens the front camera, or the back one; the caller checked the camera permission. */
    fun open(front: Boolean) = handler.post {
        this.front = front
        orientation.enable()
        start()
    }

    /** Switches between the front and back cameras. */
    fun switchCamera() = handler.post {
        if (closed) return@post
        stopCamera()
        front = !front
        start()
    }

    /**
     * Where the local preview goes, or null when it is not shown. The sender sizes it; when it is
     * replaced, [release] runs once the camera no longer draws into the old one.
     */
    fun setPreview(texture: SurfaceTexture?, release: () -> Unit = {}) = handler.post {
        val old = preview
        previewTexture = texture
        preview = texture?.let {
            it.setDefaultBufferSize(size.width, size.height)
            Surface(it)
        }
        toRelease += {
            old?.release()
            release()
        }
        if (camera != null) startSession() else releaseOld()
    }

    /** Whether frames are encoded and handed to [onFrame]; the first one after turning on is a key frame. */
    fun setSending(on: Boolean) = handler.post {
        if (sending == on) return@post
        sending = on
        updateRequest()
        if (on) requestKeyFrameNow()
    }

    fun requestKeyFrame() = handler.post { requestKeyFrameNow() }

    /** The encoder's target bitrate, in bit/s; kept within what suits the capture size. */
    fun setBitrate(bitsPerSecond: Int) = handler.post {
        bitrate = bitsPerSecond.coerceIn(MIN_BITRATE, maxBitrate())
        try {
            encoder?.setParameters(Bundle().apply { putInt(MediaCodec.PARAMETER_KEY_VIDEO_BITRATE, bitrate) })
        } catch (e: IllegalStateException) {
            debug("could not change the bitrate: $e")
        }
    }

    val maxBitrateNow: Int get() = maxBitrate()

    fun close() = handler.post {
        closed = true
        orientation.disable()
        stopCamera()
        preview?.release()
        preview = null
        thread.quitSafely()
    }

    // On the camera thread.

    private fun start() {
        if (closed) return
        if (!choose()) return stopped("no suitable camera")
        if (!startEncoder()) return stopped("no H.264 encoder for $size")
        openCamera()
    }

    /** Picks the camera facing the right way, a capture size the encoder takes, and a frame rate. */
    private fun choose(): Boolean {
        val facing = if (front) CameraCharacteristics.LENS_FACING_FRONT else CameraCharacteristics.LENS_FACING_BACK
        val ids = try {
            manager.cameraIdList.toList()
        } catch (e: Exception) {
            return false
        }
        val id = ids.firstOrNull { manager.getCameraCharacteristics(it).get(CameraCharacteristics.LENS_FACING) == facing }
            ?: ids.firstOrNull()
            ?: return false
        val characteristics = manager.getCameraCharacteristics(id)
        front = characteristics.get(CameraCharacteristics.LENS_FACING) == CameraCharacteristics.LENS_FACING_FRONT
        val map = characteristics.get(CameraCharacteristics.SCALER_STREAM_CONFIGURATION_MAP) ?: return false
        val textureSizes = map.getOutputSizes(SurfaceTexture::class.java).orEmpty().toSet()
        val capabilities = try {
            MediaCodec.createEncoderByType(MIME).let { codec ->
                codec.codecInfo.getCapabilitiesForType(MIME).videoCapabilities.also { codec.release() }
            }
        } catch (e: Exception) {
            null
        } ?: return false
        val sizes = map.getOutputSizes(MediaCodec::class.java).orEmpty().filter {
            it.width <= maxWidth && it.height <= maxHeight && it in textureSizes &&
                capabilities.areSizeAndRateSupported(it.width, it.height, frameRate.toDouble())
        }
        val wide = sizes.filter { it.width * 9 == it.height * 16 }
        size = (wide.maxByOrNull { it.width * it.height } ?: sizes.maxByOrNull { it.width * it.height }) ?: return false
        captureSize = size
        cameraId = id
        sensorOrientation = characteristics.get(CameraCharacteristics.SENSOR_ORIENTATION) ?: 0
        // Up to 30 frames a second (15 in a group call), as few as the camera likes in the dark.
        val ranges = characteristics.get(CameraCharacteristics.CONTROL_AE_AVAILABLE_TARGET_FPS_RANGES).orEmpty()
        fpsRange = (ranges.filter { it.upper == frameRate }.takeIf { it.isNotEmpty() } ?: ranges.filter { it.upper == FRAME_RATE })
            .minByOrNull { it.lower }
        previewTexture?.let {
            it.setDefaultBufferSize(size.width, size.height)
        }
        return true
    }

    private fun startEncoder(): Boolean {
        val codec = try {
            MediaCodec.createEncoderByType(MIME)
        } catch (e: Exception) {
            return false
        }
        val cbr = codec.codecInfo.getCapabilitiesForType(MIME).encoderCapabilities
            ?.isBitrateModeSupported(MediaCodecInfo.EncoderCapabilities.BITRATE_MODE_CBR) == true
        bitrate = bitrate.coerceIn(MIN_BITRATE, maxBitrate())
        fun format(withProfile: Boolean) = MediaFormat.createVideoFormat(MIME, size.width, size.height).apply {
            setInteger(MediaFormat.KEY_COLOR_FORMAT, MediaCodecInfo.CodecCapabilities.COLOR_FormatSurface)
            setInteger(MediaFormat.KEY_BIT_RATE, bitrate)
            setInteger(MediaFormat.KEY_FRAME_RATE, frameRate)
            setInteger(MediaFormat.KEY_I_FRAME_INTERVAL, KEY_FRAME_INTERVAL_S)
            setInteger(MediaFormat.KEY_PRIORITY, 0)
            // Constant bitrate: frame sizes say less about what the camera sees (§8.6).
            if (cbr) setInteger(MediaFormat.KEY_BITRATE_MODE, MediaCodecInfo.EncoderCapabilities.BITRATE_MODE_CBR)
            if (withProfile) {
                setInteger(MediaFormat.KEY_PROFILE, MediaCodecInfo.CodecProfileLevel.AVCProfileBaseline)
                setInteger(MediaFormat.KEY_LEVEL, MediaCodecInfo.CodecProfileLevel.AVCLevel31)
            }
        }
        codec.setCallback(encoderCallback, handler)
        val configured = listOf(true, false).any { withProfile ->
            try {
                codec.configure(format(withProfile), null, null, MediaCodec.CONFIGURE_FLAG_ENCODE)
                true
            } catch (e: Exception) {
                debug("encoder refused ${if (withProfile) "the baseline profile" else "the format"}: $e")
                codec.reset()
                codec.setCallback(encoderCallback, handler)
                false
            }
        }
        if (!configured) {
            codec.release()
            return false
        }
        encoderSurface = codec.createInputSurface()
        codec.start()
        encoder = codec
        codecConfig = null
        return true
    }

    @SuppressLint("MissingPermission") // The caller checks the camera permission first.
    private fun openCamera() {
        val id = cameraId ?: return
        try {
            manager.openCamera(id, executor, object : CameraDevice.StateCallback() {
                override fun onOpened(device: CameraDevice) {
                    if (closed || cameraId != id || camera != null) return device.close()
                    camera = device
                    startSession()
                }

                override fun onDisconnected(device: CameraDevice) {
                    device.close()
                    if (camera === device) stopped("camera disconnected")
                }

                override fun onError(device: CameraDevice, error: Int) {
                    device.close()
                    if (camera === device) stopped("camera error $error")
                }
            })
        } catch (e: Exception) {
            stopped("could not open the camera: $e")
        }
    }

    private fun startSession() {
        val camera = camera ?: return
        session?.close()
        session = null
        val surfaces = listOfNotNull(encoderSurface, preview)
        val outputs = surfaces.map { OutputConfiguration(it) }
        try {
            camera.createCaptureSession(
                SessionConfiguration(SessionConfiguration.SESSION_REGULAR, outputs, executor, object : CameraCaptureSession.StateCallback() {
                    override fun onConfigured(created: CameraCaptureSession) {
                        // The previous session is closed by now.
                        releaseOld()
                        if (this@CameraSender.camera !== camera || listOfNotNull(encoderSurface, preview) != surfaces) {
                            return created.close()
                        }
                        session = created
                        updateRequest()
                    }

                    override fun onConfigureFailed(failed: CameraCaptureSession) {
                        releaseOld()
                        failed.close()
                        if (this@CameraSender.camera === camera) stopped("camera session failed")
                    }
                }),
            )
        } catch (e: Exception) {
            stopped("could not start the camera session: $e")
        }
    }

    /** Draws into the preview, and into the encoder while sending. */
    private fun updateRequest() {
        val (camera, session) = (camera ?: return) to (session ?: return)
        val targets = listOfNotNull(preview, encoderSurface?.takeIf { sending })
        try {
            if (targets.isEmpty()) return session.stopRepeating()
            val request = camera.createCaptureRequest(CameraDevice.TEMPLATE_RECORD).apply {
                targets.forEach(::addTarget)
                fpsRange?.let { set(CaptureRequest.CONTROL_AE_TARGET_FPS_RANGE, it) }
            }
            session.setRepeatingRequest(request.build(), null, handler)
        } catch (e: Exception) {
            debug("could not update the capture request: $e")
        }
    }

    private fun requestKeyFrameNow() {
        try {
            encoder?.setParameters(Bundle().apply { putInt(MediaCodec.PARAMETER_KEY_REQUEST_SYNC_FRAME, 0) })
        } catch (e: IllegalStateException) {
            debug("could not ask for a key frame: $e")
        }
    }

    private val encoderCallback = object : MediaCodec.Callback() {
        override fun onInputBufferAvailable(codec: MediaCodec, index: Int) = Unit

        override fun onOutputBufferAvailable(codec: MediaCodec, index: Int, info: MediaCodec.BufferInfo) {
            if (codec !== encoder) return
            try {
                val buffer = codec.getOutputBuffer(index) ?: return
                if (info.size > 0) {
                    buffer.position(info.offset)
                    buffer.limit(info.offset + info.size)
                    val bytes = ByteArray(info.size).also { buffer.get(it) }
                    if (info.flags and MediaCodec.BUFFER_FLAG_CODEC_CONFIG != 0) {
                        codecConfig = bytes
                    } else {
                        val key = info.flags and MediaCodec.BUFFER_FLAG_KEY_FRAME != 0
                        val config = codecConfig
                        val frame = if (key && config != null && !startsWithSps(bytes)) {
                            (config + bytes).also { bytes.fill(0) }
                        } else {
                            bytes
                        }
                        onFrame(frame, key, rotation(), size.width, size.height)
                    }
                }
            } catch (e: IllegalStateException) {
                debug("encoder output failed: $e")
            } finally {
                try {
                    codec.releaseOutputBuffer(index, false)
                } catch (_: IllegalStateException) {
                }
            }
        }

        override fun onError(codec: MediaCodec, e: MediaCodec.CodecException) {
            if (codec === encoder) stopped("encoder error: $e")
        }

        override fun onOutputFormatChanged(codec: MediaCodec, format: MediaFormat) = Unit
    }

    /** Quarter turns clockwise that show the sensor's picture upright, as the device is held now. */
    private fun rotation(): Int {
        var device = (deviceOrientation + 45) / 90 * 90
        if (front) device = -device
        return ((sensorOrientation + device + 360) % 360) / 90
    }

    private fun maxBitrate(): Int = (size.width * size.height * MAX_BITS_PER_PIXEL).toInt().coerceAtLeast(MIN_BITRATE)

    private fun releaseOld() {
        toRelease.forEach { it() }
        toRelease.clear()
    }

    private fun stopped(why: String) {
        debug("camera stopped: $why")
        stopCamera()
        onStopped()
    }

    private fun stopCamera() {
        try {
            session?.close()
        } catch (_: Exception) {
        }
        session = null
        camera?.close()
        camera = null
        encoder?.let {
            try {
                it.stop()
            } catch (_: IllegalStateException) {
            }
            it.release()
        }
        encoder = null
        encoderSurface?.release()
        encoderSurface = null
        codecConfig?.fill(0)
        codecConfig = null
        releaseOld()
    }

    private fun debug(message: String) {
        if (BuildConfig.DEBUG) Log.d(TAG, message)
    }

    companion object {
        private const val TAG = "AirChat"
        private const val MIME = MediaFormat.MIMETYPE_VIDEO_AVC
        /** What devices send at most (§8.6). */
        private const val MAX_WIDTH = 1280
        private const val MAX_HEIGHT = 720
        private const val FRAME_RATE = 30
        /** In a group call, at most 640 pixels a side and 15 frames a second (§9.9). */
        private const val GROUP_MAX_SIDE = 640
        private const val GROUP_FRAME_RATE = 15
        private const val KEY_FRAME_INTERVAL_S = 2
        const val START_BITRATE = 1_500_000
        const val MIN_BITRATE = 250_000
        /** 720p at 30 frames a second gets about 2.5 Mbit/s at most. */
        private const val MAX_BITS_PER_PIXEL = 2.7

        /** Whether an Annex B frame begins with a sequence parameter set. */
        fun startsWithSps(frame: ByteArray): Boolean {
            val start = when {
                frame.size > 4 && frame[0] == 0.toByte() && frame[1] == 0.toByte() && frame[2] == 0.toByte() && frame[3] == 1.toByte() -> 4
                frame.size > 3 && frame[0] == 0.toByte() && frame[1] == 0.toByte() && frame[2] == 1.toByte() -> 3
                else -> return false
            }
            return frame[start].toInt() and 0x1f == 7
        }
    }
}
