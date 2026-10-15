package com.plyg.airchat.ui

import android.content.ContentResolver
import android.content.Context
import android.graphics.Bitmap
import android.graphics.Color
import android.graphics.ImageDecoder
import android.graphics.pdf.PdfRenderer
import android.media.MediaDataSource
import android.media.MediaMetadataRetriever
import android.net.Uri
import android.os.Build
import android.os.ParcelFileDescriptor
import android.provider.OpenableColumns
import android.system.ErrnoException
import android.system.Os
import android.system.OsConstants
import android.util.Log
import android.util.Size
import com.plyg.airchat.BuildConfig
import com.plyg.airchat.core.Account
import com.plyg.airchat.core.CoreException
import com.plyg.airchat.core.maxThumbnailBytes
import java.io.ByteArrayOutputStream
import java.io.Closeable
import java.io.FileDescriptor
import java.io.IOException
import java.nio.ByteBuffer

/**
 * Files moving between the user's storage and AirChat's encrypted store (requirements S-2, S-10).
 * Content only ever passes through memory here: nothing is cached, and pictures are decoded from
 * bytes rather than through an image library that would keep a disk cache.
 */
object Files {
    /** Bytes handed to the core per call when importing, and read per call when exporting. */
    const val PIECE = 256 * 1024

    /** Largest file shown in the in-app image viewer; larger ones can only be saved. */
    const val MAX_VIEWABLE_IMAGE = 64L * 1024 * 1024
    const val MAX_VIEWABLE_TEXT = 1024L * 1024

    /** What the user picked to send. */
    class Picked(val name: String, val mime: String, val size: Long?)

    fun describe(resolver: ContentResolver, uri: Uri): Picked {
        var name: String? = null
        var size: Long? = null
        resolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME, OpenableColumns.SIZE), null, null, null)?.use { cursor ->
            if (cursor.moveToFirst()) {
                cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME).takeIf { it >= 0 && !cursor.isNull(it) }
                    ?.let { name = cursor.getString(it) }
                cursor.getColumnIndex(OpenableColumns.SIZE).takeIf { it >= 0 && !cursor.isNull(it) }
                    ?.let { size = cursor.getLong(it) }
            }
        }
        val mime = resolver.getType(uri)?.lowercase()?.takeIf(::isMime) ?: "application/octet-stream"
        return Picked(cleanName(name), mime, size)
    }

    /** A name the core accepts: no control characters, at most 255 UTF-8 bytes, extension kept. */
    fun cleanName(name: String?): String {
        val clean = name.orEmpty().filterNot { it.isISOControl() }.trim().ifEmpty { "file" }
        if (clean.encodeToByteArray().size <= MAX_NAME_BYTES) return clean
        val dot = clean.lastIndexOf('.')
        val extension = if (dot > 0 && clean.length - dot <= 16) clean.substring(dot) else ""
        var stem = clean.removeSuffix(extension)
        while ((stem + extension).encodeToByteArray().size > MAX_NAME_BYTES) stem = stem.dropLast(1)
        // Do not leave half a surrogate pair behind.
        if (stem.lastOrNull()?.isHighSurrogate() == true) stem = stem.dropLast(1)
        return stem + extension
    }

    private fun isMime(value: String) =
        value.length in 3..127 && '/' in value && value.all { it in '!'..'~' }

    /**
     * A small JPEG of a picture or video, shown before the file is fetched; null for other files or
     * when no picture can be made. Never fails: a file is sent without a thumbnail rather than not.
     */
    fun thumbnail(context: Context, uri: Uri, mime: String): ByteArray? {
        val video = mime.startsWith("video/")
        if (!mime.startsWith("image/") && !video) return null
        return try {
            val bitmap = try {
                context.contentResolver.loadThumbnail(uri, Size(THUMBNAIL_PX, THUMBNAIL_PX), null)
            } catch (e: Exception) {
                // Providers fail in many ways here (IOException, UnsupportedOperationException, …).
                if (BuildConfig.DEBUG) Log.d(TAG, "no system thumbnail: $e")
                if (video) videoFrame(context, uri) else decode(ImageDecoder.createSource(context.contentResolver, uri), THUMBNAIL_PX)
            }
            bitmap?.let(::compressThumbnail)
        } catch (e: Exception) {
            if (BuildConfig.DEBUG) Log.d(TAG, "no thumbnail: $e")
            null
        } catch (_: OutOfMemoryError) {
            null
        }
    }

    /** A frame from early in a video, read through the content resolver. */
    private fun videoFrame(context: Context, uri: Uri): Bitmap? {
        val retriever = MediaMetadataRetriever()
        return try {
            retriever.setDataSource(context, uri)
            retriever.getScaledFrameAtTime(VIDEO_FRAME_US, MediaMetadataRetriever.OPTION_CLOSEST_SYNC, THUMBNAIL_PX, THUMBNAIL_PX)
        } catch (e: RuntimeException) {
            if (BuildConfig.DEBUG) Log.d(TAG, "no video frame: $e")
            null
        } finally {
            retriever.release()
        }
    }

    private fun compressThumbnail(bitmap: Bitmap): ByteArray? {
        val limit = maxThumbnailBytes().toInt()
        for (side in intArrayOf(THUMBNAIL_PX, THUMBNAIL_PX / 2)) {
            val scaled = scaleDown(bitmap, side)
            for (quality in intArrayOf(70, 50, 30)) {
                val out = ByteArrayOutputStream()
                scaled.compress(Bitmap.CompressFormat.JPEG, quality, out)
                if (out.size() <= limit) return out.toByteArray()
            }
        }
        return null
    }

    private fun scaleDown(bitmap: Bitmap, side: Int): Bitmap {
        val scale = side.toFloat() / maxOf(bitmap.width, bitmap.height)
        if (scale >= 1f) return bitmap
        return Bitmap.createScaledBitmap(bitmap, (bitmap.width * scale).toInt().coerceAtLeast(1), (bitmap.height * scale).toInt().coerceAtLeast(1), true)
    }

    /** Decodes a picture no larger than [maxSide] pixels on its longer side; EXIF rotation applied. */
    fun decode(source: ImageDecoder.Source, maxSide: Int): Bitmap? = try {
        ImageDecoder.decodeBitmap(source) { decoder, info, _ ->
            val longest = maxOf(info.size.width, info.size.height)
            var sample = 1
            while (longest / (sample * 2) >= maxSide) sample *= 2
            decoder.setTargetSampleSize(sample)
            // Software memory, so the bitmap can be scaled and compressed.
            decoder.allocator = ImageDecoder.ALLOCATOR_SOFTWARE
        }
    } catch (_: IOException) {
        null
    } catch (_: IllegalArgumentException) {
        null
    }

    fun decode(bytes: ByteArray, maxSide: Int): Bitmap? = decode(ImageDecoder.createSource(ByteBuffer.wrap(bytes)), maxSide)

    /** The whole of a stored file, read from the encrypted store into memory. */
    fun readAll(account: Account, file: Long, size: Long): ByteArray {
        val out = ByteArray(size.toInt())
        var position = 0
        while (position < out.size) {
            val piece = account.readFile(file, position.toULong(), minOf(PIECE, out.size - position).toUInt())
            if (piece.isEmpty()) throw IOException("stored file ends early")
            piece.copyInto(out, position)
            position += piece.size
            piece.fill(0)
        }
        return out
    }

    /**
     * A PDF from the encrypted store, rendered page by page. The platform's renderer needs a seekable
     * file descriptor, so the document is copied into anonymous memory (`memfd`), never into a file.
     * Android 11+; null before, or when it is not a readable PDF.
     */
    fun openPdf(account: Account, file: Long, size: Long): PdfDocument? {
        if (Build.VERSION.SDK_INT < 30) return null
        val memory = try {
            Os.memfd_create("airchat-view", OsConstants.MFD_CLOEXEC)
        } catch (_: ErrnoException) {
            return null
        }
        try {
            var position = 0L
            while (position < size) {
                val piece = account.readFile(file, position.toULong(), PIECE.toUInt())
                if (piece.isEmpty()) throw IOException("stored file ends early")
                writeFully(memory, piece)
                position += piece.size
                piece.fill(0)
            }
            Os.lseek(memory, 0, OsConstants.SEEK_SET)
            val descriptor = ParcelFileDescriptor.dup(memory)
            return try {
                PdfDocument(descriptor)
            } catch (e: Exception) {
                descriptor.close()
                if (e !is IOException && e !is SecurityException) throw e
                null
            }
        } catch (_: ErrnoException) {
            return null
        } finally {
            Os.close(memory)
        }
    }

    private fun writeFully(descriptor: FileDescriptor, bytes: ByteArray) {
        var offset = 0
        while (offset < bytes.size) offset += Os.write(descriptor, bytes, offset, bytes.size - offset)
    }

    /** An open PDF; render pages from any thread, close when done. */
    class PdfDocument(private val descriptor: ParcelFileDescriptor) : Closeable {
        private val renderer = PdfRenderer(descriptor)
        private var closed = false
        val pageCount: Int = renderer.pageCount

        /** Page [index] at [width] pixels wide, on white; null once closed. */
        fun render(index: Int, width: Int): Bitmap? = synchronized(this) {
            if (closed) return null
            renderer.openPage(index).use { page ->
                val height = (width.toLong() * page.height / page.width.coerceAtLeast(1)).toInt().coerceIn(1, MAX_PAGE_PX)
                val bitmap = Bitmap.createBitmap(width, height, Bitmap.Config.ARGB_8888)
                bitmap.eraseColor(Color.WHITE)
                page.render(bitmap, null, null, PdfRenderer.Page.RENDER_MODE_FOR_DISPLAY)
                bitmap
            }
        }

        override fun close() = synchronized(this) {
            if (closed) return
            closed = true
            renderer.close()
            descriptor.close()
        }
    }

    /** Lets the platform's media player read a stored file straight from the encrypted store. */
    class StoredSource(private val account: Account, private val file: Long, private val size: Long) : MediaDataSource() {
        override fun readAt(position: Long, buffer: ByteArray, offset: Int, size: Int): Int {
            if (position >= this.size) return -1
            if (size == 0) return 0
            val piece = try {
                account.readFile(file, position.toULong(), minOf(size, PIECE).toUInt())
            } catch (_: CoreException) {
                // Locked meanwhile, or the file was deleted.
                return -1
            }
            piece.copyInto(buffer, offset)
            piece.fill(0)
            return piece.size.takeIf { it > 0 } ?: -1
        }

        override fun getSize(): Long = size

        override fun close() = Unit
    }

    private const val MAX_NAME_BYTES = 255
    private const val THUMBNAIL_PX = 320
    private const val VIDEO_FRAME_US = 1_000_000L
    private const val MAX_PAGE_PX = 8192
    private const val TAG = "AirChat"
}
