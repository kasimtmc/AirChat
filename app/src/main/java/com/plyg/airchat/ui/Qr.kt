package com.plyg.airchat.ui

import android.util.Log
import androidx.camera.core.CameraSelector
import androidx.camera.core.ImageAnalysis
import androidx.camera.core.ImageProxy
import androidx.camera.core.Preview
import androidx.camera.lifecycle.ProcessCameraProvider
import androidx.camera.view.PreviewView
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.layout.aspectRatio
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberUpdatedState
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.viewinterop.AndroidView
import androidx.core.content.ContextCompat
import androidx.lifecycle.compose.LocalLifecycleOwner
import com.google.zxing.BarcodeFormat
import com.google.zxing.BinaryBitmap
import com.google.zxing.DecodeHintType
import com.google.zxing.EncodeHintType
import com.google.zxing.NotFoundException
import com.google.zxing.PlanarYUVLuminanceSource
import com.google.zxing.common.HybridBinarizer
import com.google.zxing.qrcode.QRCodeReader
import com.google.zxing.qrcode.QRCodeWriter
import com.google.zxing.qrcode.decoder.ErrorCorrectionLevel
import com.plyg.airchat.BuildConfig
import java.util.concurrent.Executors

/** A QR code of [text], drawn in memory (dark on white, with a quiet zone). */
@Composable
fun QrCode(text: String, modifier: Modifier = Modifier) {
    val matrix = remember(text) {
        QRCodeWriter().encode(
            text,
            BarcodeFormat.QR_CODE,
            0,
            0,
            mapOf(EncodeHintType.ERROR_CORRECTION to ErrorCorrectionLevel.M, EncodeHintType.MARGIN to 4),
        )
    }
    Canvas(modifier.aspectRatio(1f)) {
        drawRect(Color.White)
        val cell = size.width / matrix.width
        for (y in 0 until matrix.height) {
            for (x in 0 until matrix.width) {
                if (matrix[x, y]) drawRect(Color.Black, Offset(x * cell, y * cell), Size(cell + 0.5f, cell + 0.5f))
            }
        }
    }
}

/**
 * The back camera's picture, read for QR codes; [onRead] gets the first one's text. Frames are
 * decoded in memory as they come and never kept. Needs the camera permission.
 */
@Composable
fun QrScanner(onRead: (String) -> Unit, modifier: Modifier = Modifier) {
    val context = LocalContext.current
    val lifecycle = LocalLifecycleOwner.current
    val read = rememberUpdatedState(onRead)
    val view = remember { PreviewView(context) }
    DisposableEffect(lifecycle) {
        val executor = Executors.newSingleThreadExecutor()
        val future = ProcessCameraProvider.getInstance(context)
        var done = false
        val reader = QRCodeReader()
        val hints = mapOf(DecodeHintType.POSSIBLE_FORMATS to listOf(BarcodeFormat.QR_CODE))
        val analysis = ImageAnalysis.Builder()
            .setBackpressureStrategy(ImageAnalysis.STRATEGY_KEEP_ONLY_LATEST)
            .build()
            .also { analysis ->
                analysis.setAnalyzer(executor) { image ->
                    image.use {
                        if (done) return@use
                        val text = decode(reader, hints, it) ?: return@use
                        done = true
                        ContextCompat.getMainExecutor(context).execute { read.value(text) }
                    }
                }
            }
        future.addListener({
            val provider = future.get()
            val preview = Preview.Builder().build().also { it.surfaceProvider = view.surfaceProvider }
            try {
                provider.unbindAll()
                provider.bindToLifecycle(lifecycle, CameraSelector.DEFAULT_BACK_CAMERA, preview, analysis)
            } catch (e: Exception) {
                if (BuildConfig.DEBUG) Log.w("AirChat", "camera unavailable", e)
            }
        }, ContextCompat.getMainExecutor(context))
        onDispose {
            done = true
            runCatching { future.get().unbindAll() }
            executor.shutdown()
        }
    }
    AndroidView({ view }, modifier)
}

/** The QR code in a camera frame's brightness plane, if any. */
private fun decode(reader: QRCodeReader, hints: Map<DecodeHintType, Any>, image: ImageProxy): String? {
    val plane = image.planes[0]
    val buffer = plane.buffer
    val data = ByteArray(buffer.remaining()).also(buffer::get)
    return try {
        val source = PlanarYUVLuminanceSource(data, plane.rowStride, image.height, 0, 0, image.width, image.height, false)
        reader.decode(BinaryBitmap(HybridBinarizer(source)), hints).text
    } catch (_: NotFoundException) {
        null
    } catch (_: Exception) {
        null
    } finally {
        data.fill(0)
        reader.reset()
    }
}
