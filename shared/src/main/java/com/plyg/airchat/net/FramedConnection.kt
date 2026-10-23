package com.plyg.airchat.net

import android.os.SystemClock
import android.util.Log
import com.plyg.airchat.shared.BuildConfig
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeoutOrNull
import java.io.BufferedInputStream
import java.io.BufferedOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.IOException
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong

/**
 * One connection carrying length-prefixed frames (rust/airchat-protocol/docs/protocol.md §7.1), over any transport. The
 * bytes are opaque here: the Rust core decides what they mean.
 *
 * Outgoing frames go through a queue drained by one writer, so they leave in exactly the order the
 * core produced them, and senders never block on the network.
 */
class FramedConnection(val id: Long, val kind: TransportKind, private val stream: StreamChannel) {
    /** `null` means: close once everything queued before it has been written. */
    private val outbox = Channel<ByteArray?>(Channel.UNLIMITED)
    private val closed = AtomicBoolean(false)
    private val queued = AtomicLong(0)

    /** Bytes waiting in the queue: video holds back while the link cannot keep up. */
    val backlog: Long get() = queued.get()

    /**
     * [SystemClock.elapsedRealtime] when a large frame (a file's chunk, video) last went either way:
     * a link moved to a hotspot stays while it carries such things.
     */
    @Volatile var bulkAt = 0L
        private set

    fun start(scope: CoroutineScope, onFrame: (ByteArray) -> Unit, onClosed: () -> Unit) {
        val finish = {
            if (closed.compareAndSet(false, true)) {
                closeSocket()
                onClosed()
            }
        }
        val peerDone = CompletableDeferred<Unit>()
        scope.launch(Dispatchers.IO) {
            try {
                // A Bluetooth socket drops whatever is still queued below it when it is closed, unlike
                // TCP. After the last frame, give the peer time to read it and close first.
                if (writeAll() && kind != TransportKind.LAN) withTimeoutOrNull(LINGER_MS) { peerDone.await() }
            } finally {
                finish()
            }
        }
        scope.launch(Dispatchers.IO) {
            try {
                val input = DataInputStream(BufferedInputStream(stream.input))
                while (true) {
                    val length = input.readInt()
                    if (length !in 1..MAX_FRAME) break
                    val frame = ByteArray(length).also { input.readFully(it) }
                    if (BuildConfig.DEBUG) Log.d(TAG, "$kind #$id received $length bytes")
                    if (length >= BULK_FRAME) bulkAt = SystemClock.elapsedRealtime()
                    onFrame(frame)
                }
            } catch (e: IOException) {
                if (BuildConfig.DEBUG) Log.d(TAG, "$kind #$id reading ended: $e")
            } finally {
                peerDone.complete(Unit)
                outbox.close()
                finish()
            }
        }
    }

    /** Writes queued frames until told to close (true) or the stream fails (false). */
    private suspend fun writeAll(): Boolean {
        try {
            val output = DataOutputStream(BufferedOutputStream(stream.output))
            for (frame in outbox) {
                if (frame == null) return true
                output.writeInt(frame.size)
                output.write(frame)
                output.flush()
                queued.addAndGet(-frame.size.toLong())
                if (BuildConfig.DEBUG) Log.d(TAG, "$kind #$id sent ${frame.size} bytes")
            }
        } catch (e: IOException) {
            if (BuildConfig.DEBUG) Log.d(TAG, "$kind #$id writing failed: $e")
        }
        return false
    }

    fun send(frame: ByteArray) {
        require(frame.size in 1..MAX_FRAME) { "frame length ${frame.size} out of range" }
        queued.addAndGet(frame.size.toLong())
        if (frame.size >= BULK_FRAME) bulkAt = SystemClock.elapsedRealtime()
        outbox.trySend(frame)
    }

    fun closeAfterSending() {
        outbox.trySend(null)
    }

    private fun closeSocket() {
        try {
            stream.close()
        } catch (_: IOException) {
        }
    }

    companion object {
        private const val TAG = "AirChat"
        const val MAX_FRAME = 65_536
        /** Larger than any message or signalling record, smaller than a file chunk (15 KiB). */
        private const val BULK_FRAME = 4_096
        private const val LINGER_MS = 3_000L
    }
}
