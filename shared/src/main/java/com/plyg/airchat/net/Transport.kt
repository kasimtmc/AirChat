package com.plyg.airchat.net

import kotlinx.coroutines.flow.StateFlow
import java.io.Closeable
import java.io.InputStream
import java.io.OutputStream
import java.net.Socket

/**
 * The ways AirChat reaches other devices (rust/airchat-protocol/docs/protocol.md §7), in order of preference: a link moves
 * to an earlier one when it becomes available. A hotspot is opened only on demand (§8.3). [RELAY] is
 * a path through Air Providers (§12), which the core carries over other links itself.
 */
enum class TransportKind { LAN, AWARE, HOTSPOT, RELAY, BLE }

/**
 * A connected byte stream: a TCP socket or a Bluetooth L2CAP channel. Frames on it follow
 * rust/airchat-protocol/docs/protocol.md §7.1 whatever carries them.
 */
interface StreamChannel : Closeable {
    val input: InputStream
    val output: OutputStream
}

fun Socket.asStreamChannel(): StreamChannel {
    forMedia()
    return object : StreamChannel {
        override val input: InputStream get() = getInputStream()
        override val output: OutputStream get() = getOutputStream()
        override fun close() = this@asStreamChannel.close()
    }
}

/**
 * Small frames (audio) leave at once, and the kernel holds little: what waits to be sent waits in
 * [FramedConnection]'s queue, where video can see it and hold back (docs/architecture.md §6),
 * not seconds of it below, where audio would queue behind it. Local links have short round trips,
 * so this costs no throughput.
 */
fun Socket.forMedia() {
    try {
        tcpNoDelay = true
        sendBufferSize = SEND_BUFFER_BYTES
    } catch (_: java.net.SocketException) {
    }
}

private const val SEND_BUFFER_BYTES = 64 * 1024

/** One announcement of another device, as one transport sees it. */
interface Peer {
    val kind: TransportKind
    /** Present while the device has "Add nearby" open (rust/airchat-protocol/docs/protocol.md §5.1). */
    val pairingToken: ByteArray?
    /** Lets a contact recognise the device (rust/airchat-protocol/docs/protocol.md §5.2). */
    val presenceToken: ByteArray?
    /** The walkie-talkie channel the device is tuned to, for its members (rust/airchat-protocol/docs/protocol.md §11.2). */
    val channelToken: ByteArray?
    /** A request to add the owner of an AirChat ID, for that owner (rust/airchat-protocol/docs/protocol.md §4.8). */
    val requestToken: ByteArray? get() = null

    /** Opens a connection to the device. Blocking; call off the main thread. */
    fun connect(): StreamChannel
}

/**
 * Finds other devices and accepts their connections; every accepted or opened connection goes to the
 * [ConnectionHub]. Announcements carry nothing but the tokens of rust/airchat-protocol/docs/protocol.md §5. Main thread only.
 */
interface Transport {
    val kind: TransportKind
    val peers: StateFlow<List<Peer>>

    /** @throws java.io.IOException if the transport cannot run now. */
    fun start()

    fun stop()

    /** Announces the pairing token while "Add nearby" is open; `null` withdraws it. */
    fun setPairingToken(token: ByteArray?)

    /**
     * The tuned walkie-talkie channel changed: announce its token now (or withdraw it) rather than
     * at the next minute's check. Transports ask for the token themselves, like the presence token.
     */
    fun channelChanged() {}

    /** The request to announce changed (rust/airchat-protocol/docs/protocol.md §4.8); asked for like the channel's. */
    fun requestChanged() {}

    /**
     * Starts discovery and announcements afresh, in case the platform stopped them without telling
     * (seen with BLE on MIUI in the background). Called when the app comes to the front.
     */
    fun refresh() {}
}
