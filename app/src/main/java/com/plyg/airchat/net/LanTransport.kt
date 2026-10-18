package com.plyg.airchat.net

import android.content.Context
import android.net.ConnectivityManager
import android.net.LinkAddress
import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.net.nsd.NsdManager
import android.net.nsd.NsdServiceInfo
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.util.Log
import com.plyg.airchat.BuildConfig
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.suspendCancellableCoroutine
import java.io.IOException
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.NetworkInterface
import java.net.ServerSocket
import java.net.Socket
import java.security.SecureRandom
import kotlin.coroutines.resume

/** Another AirChat device on the local network: one of its DNS-SD services. */
class LanPeer(
    val serviceName: String,
    val host: InetAddress,
    val port: Int,
    override val pairingToken: ByteArray?,
    override val presenceToken: ByteArray?,
    override val channelToken: ByteArray?,
    override val requestToken: ByteArray? = null,
) : Peer {
    override val kind get() = TransportKind.LAN

    /** Announces the same token, so it is the same device, perhaps as a new service after a restart. */
    fun sameDeviceAs(other: LanPeer) =
        presenceToken?.contentEquals(other.presenceToken) == true ||
            pairingToken?.contentEquals(other.pairingToken) == true ||
            channelToken?.contentEquals(other.channelToken) == true ||
            requestToken?.contentEquals(other.requestToken) == true

    override fun connect(): StreamChannel {
        val socket = Socket()
        try {
            socket.connect(InetSocketAddress(host, port), CONNECT_TIMEOUT_MS)
        } catch (e: IOException) {
            socket.close()
            throw e
        }
        return socket.asStreamChannel()
    }

    private companion object {
        const val CONNECT_TIMEOUT_MS = 5_000
    }
}

/**
 * Local network transport (rust/airchat-protocol/docs/protocol.md §7.2): a TCP server announced over DNS-SD, and discovery
 * of other devices doing the same. Announcements carry no name or identity: a random instance name,
 * the presence token that only contacts recognise, and, while "Add nearby" is open, the pairing token.
 *
 * [presenceToken] is asked again every minute; when it changes (hourly) the service is re-announced
 * under a new random name, so the old and new announcements cannot be linked by name.
 *
 * Android announces and looks on every network. A phone on two Wi-Fi networks of one router (MIUI's
 * dual Wi-Fi: its 2.4 and 5 GHz networks) then announces each service twice on one LAN, under two
 * host names; each announcement takes the other for a conflicting device and renames the service,
 * every few seconds without end, and a device behind NAT never finds it. While two Wi-Fi networks
 * share a subnet, both run on one of them only (from Android 13, which takes a network for both).
 */
class LanTransport(
    context: Context,
    private val hub: ConnectionHub,
    private val scope: CoroutineScope,
    private val presenceToken: () -> ByteArray,
    private val channelToken: () -> ByteArray?,
    private val requestToken: () -> ByteArray?,
) : Transport {
    override val kind get() = TransportKind.LAN
    private val nsd = context.getSystemService(NsdManager::class.java)
    private val connectivity = context.getSystemService(ConnectivityManager::class.java)
    private val mainExecutor = context.mainExecutor
    /** The subnets of every Wi-Fi network up, link-local ones left out. */
    private val wifiSubnets = mutableMapOf<Network, Set<String>>()
    private var networkWatch: ConnectivityManager.NetworkCallback? = null
    /** The one network announcements and discovery run on, or null for all of them. */
    private var onlyOn: Network? = null
    /** The names this device announced lately: a withdrawn service lingers a while in caches. */
    private val ownNames = ArrayDeque<String>()
    private var announcedPresence: ByteArray? = null
    private var rotation: Job? = null
    private var server: ServerSocket? = null
    private var registration: NsdManager.RegistrationListener? = null
    /**
     * While "Add nearby" is open, a second service with its own random name carries the pairing
     * token. Changing the TXT record of one service would mean re-registering the same name, and
     * the resulting "lost" and "found" events can reach other devices in either order.
     */
    private var pairingRegistration: NsdManager.RegistrationListener? = null
    private var announcedPairing: ByteArray? = null
    /** The same for the walkie-talkie channel tuned to (rust/airchat-protocol/docs/protocol.md §11.2). */
    private var channelRegistration: NsdManager.RegistrationListener? = null
    private var announcedChannel: ByteArray? = null
    /** The same for a request to add the owner of an AirChat ID (rust/airchat-protocol/docs/protocol.md §4.8). */
    private var requestRegistration: NsdManager.RegistrationListener? = null
    private var announcedRequest: ByteArray? = null
    private var discovery: NsdManager.DiscoveryListener? = null
    private val found = mutableMapOf<String, LanPeer>()
    /** Older Android versions resolve one service at a time. */
    private val toResolve = Channel<NsdServiceInfo>(Channel.UNLIMITED)

    private val _peers = MutableStateFlow<List<Peer>>(emptyList())
    override val peers: StateFlow<List<Peer>> = _peers

    override fun start() {
        val socket = ServerSocket(0)
        server = socket
        scope.launch(Dispatchers.IO) {
            try {
                while (true) hub.attach(socket.accept().asStreamChannel(), TransportKind.LAN)
            } catch (_: IOException) {
                // Closed by stop().
            }
        }
        scope.launch {
            for (service in toResolve) resolve(service)?.takeIf { onLink(it.host) }?.let(::update)
        }
        announcePresence()
        channelChanged()
        requestChanged()
        rotation = scope.launch {
            while (true) {
                delay(ROTATION_CHECK_MS)
                if (!presenceToken().contentEquals(announcedPresence)) announcePresence()
                channelChanged()
                requestChanged()
            }
        }
        startDiscovery()
        watchNetworks()
    }

    private fun announcePresence() {
        registration?.let(::unregister)
        val token = presenceToken()
        announcedPresence = token
        registration = register(randomHex(8), pairingToken = null, presenceToken = token)
    }

    override fun channelChanged() {
        if (server == null) return
        val token = channelToken()
        if (token contentEquals announcedChannel) return
        announcedChannel = token
        channelRegistration?.let(::unregister)
        channelRegistration = null
        if (token != null) {
            // A new random name for every token, so announcements of two epochs cannot be linked.
            channelRegistration = register(randomHex(8), pairingToken = null, presenceToken = null, channelToken = token)
        }
    }

    override fun requestChanged() {
        if (server == null) return
        val token = requestToken()
        if (token contentEquals announcedRequest) return
        announcedRequest = token
        requestRegistration?.let(::unregister)
        requestRegistration = null
        if (token != null) {
            requestRegistration = register(randomHex(8), pairingToken = null, presenceToken = null, requestToken = token)
        }
    }

    override fun stop() {
        rotation?.cancel()
        networkWatch?.let { runCatching { connectivity.unregisterNetworkCallback(it) } }
        networkWatch = null
        wifiSubnets.clear()
        onlyOn = null
        stopDiscovery()
        setPairingToken(null)
        channelRegistration?.let(::unregister)
        channelRegistration = null
        announcedChannel = null
        requestRegistration?.let(::unregister)
        requestRegistration = null
        announcedRequest = null
        registration?.let(::unregister)
        registration = null
        toResolve.close()
        try {
            server?.close()
        } catch (_: IOException) {
        }
        server = null
    }

    /** Announces the pairing token while "Add nearby" is open; `null` withdraws it. */
    override fun setPairingToken(token: ByteArray?) {
        announcedPairing = token
        pairingRegistration?.let(::unregister)
        pairingRegistration = null
        if (token != null) pairingRegistration = register(randomHex(8), pairingToken = token, presenceToken = null)
    }

    private fun startDiscovery() {
        if (discovery != null) return
        val listener = object : NsdManager.DiscoveryListener {
            override fun onServiceFound(service: NsdServiceInfo) {
                if (!isOwn(service.serviceName)) toResolve.trySend(service)
            }

            override fun onServiceLost(service: NsdServiceInfo) {
                synchronized(found) { found.remove(service.serviceName) }
                publish()
            }

            override fun onDiscoveryStarted(serviceType: String) = Unit
            override fun onDiscoveryStopped(serviceType: String) = Unit
            override fun onStartDiscoveryFailed(serviceType: String, errorCode: Int) = Unit
            override fun onStopDiscoveryFailed(serviceType: String, errorCode: Int) = Unit
        }
        discovery = listener
        val network = onlyOn
        if (network != null && Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            nsd.discoverServices(SERVICE_TYPE, NsdManager.PROTOCOL_DNS_SD, network, mainExecutor, listener)
        } else {
            nsd.discoverServices(SERVICE_TYPE, NsdManager.PROTOCOL_DNS_SD, listener)
        }
    }

    /** Follows the Wi-Fi networks, to notice two on one subnet (see the class comment). */
    private fun watchNetworks() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU || networkWatch != null) return
        val request = NetworkRequest.Builder()
            .addTransportType(NetworkCapabilities.TRANSPORT_WIFI)
            .removeCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            .build()
        val callback = object : ConnectivityManager.NetworkCallback() {
            override fun onLinkPropertiesChanged(network: Network, properties: LinkProperties) {
                val subnets = properties.linkAddresses
                    .filterNot { it.address.isLinkLocalAddress }
                    .map { it.subnet() }
                    .toSet()
                if (wifiSubnets[network] == subnets) return
                wifiSubnets[network] = subnets
                chooseNetwork()
            }

            override fun onLost(network: Network) {
                if (wifiSubnets.remove(network) != null) chooseNetwork()
            }
        }
        networkWatch = callback
        // On the main thread, like everything else here.
        connectivity.registerNetworkCallback(request, callback, Handler(Looper.getMainLooper()))
    }

    /**
     * While Wi-Fi networks share a subnet, announces and looks on one of them: the default network if
     * it is one, else the same one every time.
     */
    private fun chooseNetwork() {
        if (server == null) return
        val shared = wifiSubnets.filter { (network, subnets) ->
            wifiSubnets.any { (other, theirs) -> other != network && subnets.any(theirs::contains) }
        }.keys
        val chosen = when {
            shared.isEmpty() -> null
            else -> connectivity.activeNetwork?.takeIf { it in shared } ?: shared.minBy { it.networkHandle }
        }
        if (chosen == onlyOn) return
        if (BuildConfig.DEBUG) {
            Log.d(TAG, if (chosen == null) "announcing on every network" else "announcing on one of ${shared.size} on one subnet")
        }
        onlyOn = chosen
        // Every service again, under new names, and discovery on the new network(s).
        announcePresence()
        setPairingToken(announcedPairing)
        announcedChannel = null
        channelChanged()
        announcedRequest = null
        requestChanged()
        stopDiscovery()
        startDiscovery()
    }

    private fun stopDiscovery() {
        discovery?.let { runCatching { nsd.stopServiceDiscovery(it) } }
        discovery = null
        synchronized(found) { found.clear() }
        publish()
    }

    /** Android may rename a registration to "name (2)" on a conflict; never list ourselves. */
    private fun isOwn(serviceName: String) = synchronized(ownNames) { ownNames.any(serviceName::startsWith) }

    private fun register(
        name: String,
        pairingToken: ByteArray?,
        presenceToken: ByteArray?,
        channelToken: ByteArray? = null,
        requestToken: ByteArray? = null,
    ): NsdManager.RegistrationListener? {
        val port = server?.localPort ?: return null
        if (BuildConfig.DEBUG) Log.d(TAG, "registering $name on port $port")
        synchronized(ownNames) {
            ownNames.addLast(name)
            if (ownNames.size > OWN_NAMES) ownNames.removeFirst()
        }
        val info = NsdServiceInfo().apply {
            serviceName = name
            serviceType = SERVICE_TYPE
            setPort(port)
            setAttribute("v", "0")
            pairingToken?.let { setAttribute("p", it.toHex()) }
            presenceToken?.let { setAttribute("t", it.toHex()) }
            channelToken?.let { setAttribute("c", it.toHex()) }
            requestToken?.let { setAttribute("r", it.toHex()) }
            onlyOn?.let { if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) network = it }
        }
        val listener = object : NsdManager.RegistrationListener {
            override fun onServiceRegistered(info: NsdServiceInfo) = Unit
            override fun onRegistrationFailed(info: NsdServiceInfo, errorCode: Int) = Unit
            override fun onServiceUnregistered(info: NsdServiceInfo) = Unit
            override fun onUnregistrationFailed(info: NsdServiceInfo, errorCode: Int) = Unit
        }
        nsd.registerService(info, NsdManager.PROTOCOL_DNS_SD, listener)
        return listener
    }

    private fun unregister(listener: NsdManager.RegistrationListener) {
        runCatching { nsd.unregisterService(listener) }
    }

    @Suppress("DEPRECATION") // resolveService works on every supported version; its successor needs API 34.
    private suspend fun resolve(service: NsdServiceInfo): LanPeer? = suspendCancellableCoroutine { continuation ->
        nsd.resolveService(service, object : NsdManager.ResolveListener {
            override fun onServiceResolved(resolved: NsdServiceInfo) {
                fun token(key: String) = resolved.attributes[key]?.decodeToString()?.hexToBytesOrNull()
                if (BuildConfig.DEBUG) {
                    Log.d(TAG, "resolved ${resolved.serviceName} at port ${resolved.port}, keys ${resolved.attributes.keys}")
                }
                continuation.resume(
                    LanPeer(
                        resolved.serviceName, resolved.host, resolved.port, token("p"), token("t"), token("c"),
                        requestToken = token("r"),
                    ),
                )
            }

            override fun onResolveFailed(service: NsdServiceInfo, errorCode: Int) = continuation.resume(null)
        })
    }

    /**
     * Whether [address] is on a network this device is on: link-local, or in the subnet of one of its
     * interfaces (Wi-Fi, hotspot). Devices on the same Wi-Fi always are. An address elsewhere cannot
     * be reached, and connecting to it would only time out, again and again: an emulator announces
     * the address it has behind its NAT, a device on a VPN one of the VPN's.
     */
    private fun onLink(address: InetAddress): Boolean {
        if (address.isLinkLocalAddress) return true
        val interfaces = runCatching { NetworkInterface.getNetworkInterfaces()?.toList() }.getOrNull().orEmpty()
        val on = interfaces
            .filter { runCatching { it.isUp && !it.isLoopback }.getOrDefault(false) }
            .flatMap { it.interfaceAddresses }
            .any { it.address.javaClass == address.javaClass && sameSubnet(it.address, address, it.networkPrefixLength.toInt()) }
        if (!on && BuildConfig.DEBUG) Log.d(TAG, "ignoring a service at an address not on any network of this device")
        return on
    }

    private fun update(peer: LanPeer) {
        synchronized(found) {
            // A device whose app restarted announces a new service; some phones (seen on MIUI) never
            // report the old one lost, and connecting there would only time out.
            found.values.removeAll { it.serviceName != peer.serviceName && it.sameDeviceAs(peer) }
            found[peer.serviceName] = peer
        }
        publish()
    }

    private fun publish() {
        _peers.value = synchronized(found) { found.values.sortedBy { it.serviceName } }
    }

    private companion object {
        const val TAG = "AirChat"
        const val SERVICE_TYPE = "_airchat._tcp"
        const val ROTATION_CHECK_MS = 60_000L
        const val OWN_NAMES = 32

        fun randomHex(bytes: Int) = ByteArray(bytes).also(SecureRandom()::nextBytes).toHex()

        fun ByteArray.toHex() = joinToString("") { "%02x".format(it) }

        /** The subnet an address is on, as "network address/prefix length". */
        fun LinkAddress.subnet(): String {
            val bytes = address.address
            for (i in bytes.indices) {
                val kept = (prefixLength - 8 * i).coerceIn(0, 8)
                bytes[i] = (bytes[i].toInt() and (0xff shl (8 - kept))).toByte()
            }
            return "${bytes.toHex()}/$prefixLength"
        }

        /** Whether [a] and [b] agree in their first [prefixLength] bits. */
        fun sameSubnet(a: InetAddress, b: InetAddress, prefixLength: Int): Boolean {
            val x = a.address
            val y = b.address
            if (x.size != y.size || prefixLength !in 0..8 * x.size) return false
            for (i in x.indices) {
                val kept = (prefixLength - 8 * i).coerceIn(0, 8)
                val mask = 0xff shl (8 - kept) and 0xff
                if (x[i].toInt() and mask != y[i].toInt() and mask) return false
            }
            return true
        }

        fun String.hexToBytesOrNull(): ByteArray? =
            if (length % 2 != 0 || any { it !in "0123456789abcdef" }) null
            else chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    }
}
