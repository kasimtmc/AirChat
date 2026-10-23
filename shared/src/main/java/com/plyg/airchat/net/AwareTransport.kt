package com.plyg.airchat.net

import android.annotation.SuppressLint
import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.net.wifi.aware.AttachCallback
import android.net.wifi.aware.DiscoverySessionCallback
import android.net.wifi.aware.PeerHandle
import android.net.wifi.aware.PublishConfig
import android.net.wifi.aware.PublishDiscoverySession
import android.net.wifi.aware.SubscribeConfig
import android.net.wifi.aware.SubscribeDiscoverySession
import android.net.wifi.aware.WifiAwareManager
import android.net.wifi.aware.WifiAwareNetworkInfo
import android.net.wifi.aware.WifiAwareNetworkSpecifier
import android.net.wifi.aware.WifiAwareSession
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.util.Log
import com.plyg.airchat.shared.BuildConfig
import com.plyg.airchat.core.AwareBeacon
import com.plyg.airchat.core.awareConnectRequest
import com.plyg.airchat.core.awareServiceName
import com.plyg.airchat.core.decodeAwareBeacon
import com.plyg.airchat.core.encodeAwareBeacon
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.launch
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.CompletableFuture
import java.util.concurrent.ExecutionException
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException
import java.util.concurrent.atomic.AtomicInteger

/** Another AirChat device in Wi-Fi Aware range: one of its publications. */
class AwarePeer(
    private val transport: AwareTransport,
    val handle: PeerHandle,
    override val pairingToken: ByteArray?,
    override val presenceToken: ByteArray?,
    override val channelToken: ByteArray?,
    override val requestToken: ByteArray? = null,
) : Peer {
    override val kind get() = TransportKind.AWARE

    override fun connect(): StreamChannel = transport.open(handle)
}

/**
 * Wi-Fi Aware (NAN) transport (rust/airchat-protocol/docs/protocol.md §7.4): device-to-device Wi-Fi found and used without
 * a shared network, on phones that support it. Publications carry only the beacons of §5; the radio
 * addresses are random and change, and no device name is sent (requirements T-5).
 *
 * To connect, a subscriber asks the publisher for a data path with a follow-up message; both request
 * it, the publisher announces a TCP port in it, and the subscriber connects to the publisher's IPv6
 * link-local address. Main thread, except [open].
 */
@SuppressLint("MissingPermission") // The runtime starts this transport only with the Wi-Fi permissions granted.
class AwareTransport(
    context: Context,
    private val hub: ConnectionHub,
    private val scope: CoroutineScope,
    private val presenceToken: () -> ByteArray,
    private val channelToken: () -> ByteArray?,
    private val requestToken: () -> ByteArray?,
) : Transport {
    override val kind get() = TransportKind.AWARE

    private val aware: WifiAwareManager? = context.getSystemService(WifiAwareManager::class.java)
    private val connectivity = context.getSystemService(ConnectivityManager::class.java)
    private val handler = Handler(Looper.getMainLooper())
    private val serviceName = awareServiceName()
    private val messageIds = AtomicInteger()

    private var stopped = false
    private var session: WifiAwareSession? = null
    private var presence: PublishDiscoverySession? = null
    private var announcedPresence: ByteArray? = null
    private var pairing: PublishDiscoverySession? = null
    private var pairingToken: ByteArray? = null
    private var channel: PublishDiscoverySession? = null
    private var announcedChannel: ByteArray? = null
    private var request: PublishDiscoverySession? = null
    private var announcedRequest: ByteArray? = null
    @Volatile private var subscription: SubscribeDiscoverySession? = null
    private val jobs = mutableListOf<Job>()
    private val seen = mutableMapOf<PeerHandle, AwarePeer>()

    private val _peers = MutableStateFlow<List<Peer>>(emptyList())
    override val peers: StateFlow<List<Peer>> = _peers

    override fun start() {
        val aware = aware?.takeIf { it.isAvailable } ?: throw IOException("Wi-Fi Aware unavailable")
        aware.attach(
            object : AttachCallback() {
                override fun onAttached(session: WifiAwareSession) {
                    if (stopped) return session.close()
                    this@AwareTransport.session = session
                    debug { "Wi-Fi Aware attached" }
                    advertisePresence()
                    pairingToken?.let(::publishPairing)
                    announcedChannel = null
                    channelChanged()
                    announcedRequest = null
                    requestChanged()
                    subscribe()
                }

                override fun onAttachFailed() {
                    if (BuildConfig.DEBUG) Log.w(TAG, "Wi-Fi Aware attach failed")
                }
            },
            handler,
        )
        jobs += scope.launch {
            while (true) {
                delay(ROTATION_CHECK_MS)
                if (!presenceToken().contentEquals(announcedPresence)) advertisePresence()
                channelChanged()
                requestChanged()
            }
        }
        // Before Android 12 there is no "service lost": start over now and then to forget departed peers.
        if (Build.VERSION.SDK_INT < 31) {
            jobs += scope.launch {
                while (true) {
                    delay(RESUBSCRIBE_MS)
                    subscribe()
                }
            }
        }
    }

    override fun stop() {
        stopped = true
        jobs.forEach { it.cancel() }
        jobs.clear()
        listOfNotNull(presence, pairing, channel, request, subscription).forEach { runCatching { it.close() } }
        presence = null
        pairing = null
        channel = null
        announcedChannel = null
        request = null
        announcedRequest = null
        subscription = null
        session?.close()
        session = null
        seen.clear()
        publish()
    }

    override fun setPairingToken(token: ByteArray?) {
        pairingToken = token
        if (token == null) {
            pairing?.close()
            pairing = null
        } else {
            publishPairing(token)
        }
    }

    override fun channelChanged() {
        val session = session ?: return
        val token = channelToken()
        if (token contentEquals announcedChannel) return
        announcedChannel = token
        if (token == null) {
            channel?.close()
            channel = null
            return
        }
        val config = publishConfig(AwareBeacon.Channel(token)) ?: return
        channel?.let { return it.updatePublish(config) }
        session.publish(config, Publisher { channel = it }, handler)
    }

    override fun requestChanged() {
        val session = session ?: return
        val token = requestToken()
        if (token contentEquals announcedRequest) return
        announcedRequest = token
        if (token == null) {
            request?.close()
            request = null
            return
        }
        val config = publishConfig(AwareBeacon.Request(token)) ?: return
        request?.let { return it.updatePublish(config) }
        session.publish(config, Publisher { request = it }, handler)
    }

    private fun advertisePresence() {
        val token = presenceToken()
        announcedPresence = token
        val config = publishConfig(AwareBeacon.Presence(token)) ?: return
        presence?.let { return it.updatePublish(config) }
        session?.publish(config, Publisher { presence = it }, handler)
    }

    private fun publishPairing(token: ByteArray) {
        val config = publishConfig(AwareBeacon.Pairing(token)) ?: return
        pairing?.let { return it.updatePublish(config) }
        session?.publish(config, Publisher { pairing = it }, handler)
    }

    private fun publishConfig(beacon: AwareBeacon): PublishConfig? {
        val info = encodeAwareBeacon(beacon) ?: return null
        return PublishConfig.Builder()
            .setServiceName(serviceName)
            .setServiceSpecificInfo(info)
            .setPublishType(PublishConfig.PUBLISH_TYPE_UNSOLICITED)
            .build()
    }

    private fun subscribe() {
        val session = session ?: return
        subscription?.close()
        subscription = null
        seen.clear()
        publish()
        val config = SubscribeConfig.Builder()
            .setServiceName(serviceName)
            .setSubscribeType(SubscribeConfig.SUBSCRIBE_TYPE_PASSIVE)
            .build()
        session.subscribe(
            config,
            object : DiscoverySessionCallback() {
                override fun onSubscribeStarted(session: SubscribeDiscoverySession) {
                    subscription = session
                }

                override fun onServiceDiscovered(peer: PeerHandle, info: ByteArray, matchFilter: List<ByteArray>) =
                    found(peer, info)

                override fun onServiceLost(peer: PeerHandle, reason: Int) {
                    if (seen.remove(peer) != null) publish()
                }
            },
            handler,
        )
    }

    private fun found(peer: PeerHandle, info: ByteArray) {
        val found = when (val beacon = decodeAwareBeacon(info) ?: return) {
            is AwareBeacon.Presence -> AwarePeer(this, peer, null, beacon.token, null)
            is AwareBeacon.Pairing -> AwarePeer(this, peer, beacon.token, null, null)
            is AwareBeacon.Channel -> AwarePeer(this, peer, null, null, beacon.token)
            is AwareBeacon.Request -> AwarePeer(this, peer, null, null, null, requestToken = beacon.token)
        }
        // Our own publication, should the platform report it. Two absent tokens are no match.
        if (found.presenceToken?.contentEquals(announcedPresence) == true ||
            found.pairingToken?.contentEquals(pairingToken) == true ||
            found.channelToken?.contentEquals(announcedChannel) == true ||
            found.requestToken?.contentEquals(announcedRequest) == true
        ) {
            return debug { "ignored our own Wi-Fi Aware publication" }
        }
        seen[peer] = found
        debug { "heard a beacon over Wi-Fi Aware" }
        publish()
    }

    private fun publish() {
        _peers.value = seen.values.toList()
    }

    /** Answers a subscriber's data path request on one of our publications. */
    private inner class Publisher(private val started: (PublishDiscoverySession) -> Unit) : DiscoverySessionCallback() {
        private var session: PublishDiscoverySession? = null

        override fun onPublishStarted(session: PublishDiscoverySession) {
            this.session = session
            started(session)
        }

        override fun onMessageReceived(peer: PeerHandle, message: ByteArray) {
            val session = session ?: return
            if (message.contentEquals(awareConnectRequest())) serve(session, peer)
        }
    }

    private fun serve(session: PublishDiscoverySession, peer: PeerHandle) {
        val server = ServerSocket(0)
        val specifier = WifiAwareNetworkSpecifier.Builder(session, peer)
            .setPskPassphrase(DATA_PATH_PASSPHRASE)
            .setPort(server.localPort)
            .setTransportProtocol(TCP)
            .build()
        val callback = object : ConnectivityManager.NetworkCallback() {}
        connectivity.requestNetwork(dataPathRequest(specifier), callback)
        val release = {
            runCatching { server.close() }
            runCatching { connectivity.unregisterNetworkCallback(callback) }
            Unit
        }
        scope.launch(Dispatchers.IO) {
            try {
                server.soTimeout = DATA_PATH_TIMEOUT_MS
                val socket = server.accept()
                server.close()
                hub.attach(socket.withRelease(release), TransportKind.AWARE)
            } catch (_: IOException) {
                release()
            }
        }
    }

    /** Opens a data path to a publisher and a connection over it. Blocking; call off the main thread. */
    fun open(peer: PeerHandle): StreamChannel {
        val subscription = subscription ?: throw IOException("not subscribed")
        subscription.sendMessage(peer, messageIds.incrementAndGet(), awareConnectRequest())
        val specifier = WifiAwareNetworkSpecifier.Builder(subscription, peer)
            .setPskPassphrase(DATA_PATH_PASSPHRASE)
            .build()
        val ready = CompletableFuture<Pair<Network, WifiAwareNetworkInfo>>()
        val callback = object : ConnectivityManager.NetworkCallback() {
            override fun onCapabilitiesChanged(network: Network, capabilities: NetworkCapabilities) {
                val info = capabilities.transportInfo as? WifiAwareNetworkInfo ?: return
                if (info.peerIpv6Addr != null && info.port > 0) ready.complete(network to info)
            }

            override fun onUnavailable() {
                ready.completeExceptionally(IOException("no Wi-Fi Aware data path"))
            }
        }
        connectivity.requestNetwork(dataPathRequest(specifier), callback, DATA_PATH_TIMEOUT_MS)
        val release = {
            runCatching { connectivity.unregisterNetworkCallback(callback) }
            Unit
        }
        try {
            val (network, info) = ready.get(DATA_PATH_TIMEOUT_MS + 1_000L, TimeUnit.MILLISECONDS)
            val socket = network.socketFactory.createSocket()
            try {
                socket.connect(InetSocketAddress(info.peerIpv6Addr, info.port), CONNECT_TIMEOUT_MS)
            } catch (e: IOException) {
                socket.close()
                throw e
            }
            return socket.withRelease { release() }
        } catch (e: Exception) {
            release()
            throw when (e) {
                is IOException -> e
                is ExecutionException -> e.cause as? IOException ?: IOException(e)
                is TimeoutException -> IOException("Wi-Fi Aware data path timed out")
                else -> throw e
            }
        }
    }

    private fun dataPathRequest(specifier: WifiAwareNetworkSpecifier) = NetworkRequest.Builder()
        .addTransportType(NetworkCapabilities.TRANSPORT_WIFI_AWARE)
        .setNetworkSpecifier(specifier)
        .build()

    /** The connection's stream; closing it also ends the data path. */
    private fun Socket.withRelease(release: () -> Unit): StreamChannel {
        forMedia()
        return object : StreamChannel {
            override val input: InputStream get() = getInputStream()
            override val output: OutputStream get() = getOutputStream()
            override fun close() {
                this@withRelease.close()
                release()
            }
        }
    }

    private inline fun debug(message: () -> String) {
        if (BuildConfig.DEBUG) Log.d(TAG, message())
    }

    private companion object {
        const val TAG = "AirChat"
        const val ROTATION_CHECK_MS = 60_000L
        const val RESUBSCRIBE_MS = 5 * 60_000L
        const val DATA_PATH_TIMEOUT_MS = 15_000
        const val CONNECT_TIMEOUT_MS = 10_000
        const val TCP = 6

        /**
         * Not a secret (rust/airchat-protocol/docs/protocol.md §7.4): Android carries the port only on a secured data path,
         * and the link session protects everything anyway.
         */
        const val DATA_PATH_PASSPHRASE = "AirChat v0 data path"
    }
}
