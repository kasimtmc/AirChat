package com.plyg.airchat.net

import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.wifi.WifiManager
import android.util.Log
import com.plyg.airchat.BuildConfig
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.IOException
import java.net.DatagramPacket
import java.net.Inet4Address
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.MulticastSocket
import java.net.NetworkInterface
import java.net.SocketTimeoutException

/**
 * The Wi-Fi check (requirements AP-10): whether the Wi-Fi this device is on lets the devices on it
 * reach each other, as AirChat needs (rust/airchat-protocol/docs/protocol.md §7.2). Many networks in
 * cafés and hotels keep them apart (client isolation): each reaches the router only.
 *
 * A link to another AirChat device over the network settles it. Without one, the check asks once
 * which services are around, the multicast DNS query every phone and computer sends, naming nothing,
 * and listens for a few seconds: a device heard on the same subnet, the router aside, shows that
 * other devices' traffic reaches this one. Only senders' addresses are compared, in memory; what
 * they say is not read, and nothing about the network is kept or sent anywhere.
 */
class WifiCheck(context: Context) {
    enum class Result {
        /** Not on a Wi-Fi network. */
        NO_WIFI,

        /** Linked to another AirChat device over it right now. */
        WORKS,

        /** Other devices heard: devices on it most likely reach each other. */
        DEVICES_HEARD,

        /** No other device heard: alone on it, or the network keeps devices apart. */
        NONE_HEARD,
    }

    private val connectivity = context.getSystemService(ConnectivityManager::class.java)
    private val wifi = context.getSystemService(WifiManager::class.java)

    suspend fun run(linkedOverWifi: Boolean): Result = withContext(Dispatchers.IO) {
        val network = wifiNetwork() ?: return@withContext Result.NO_WIFI
        if (linkedOverWifi) return@withContext Result.WORKS
        val properties = connectivity.getLinkProperties(network) ?: return@withContext Result.NO_WIFI
        val own = properties.linkAddresses.map { it.address }.filterIsInstance<Inet4Address>()
        val subnets = properties.linkAddresses.filter { it.address is Inet4Address }
        val router = properties.routes.filter { it.isDefaultRoute && it.hasGateway() }.map { it.gateway }
        val face = properties.interfaceName?.let(NetworkInterface::getByName)
        if (subnets.isEmpty() || face == null) return@withContext Result.NO_WIFI
        fun other(address: InetAddress) =
            address is Inet4Address && address !in own && address !in router &&
                subnets.any { sameSubnet(it.address, address, it.prefixLength) }
        if (heard(network, face, ::other)) Result.DEVICES_HEARD else Result.NONE_HEARD
    }

    /** The default network if it is Wi-Fi, else a Wi-Fi network without internet access (a router alone). */
    @Suppress("DEPRECATION") // allNetworks: its successor is a callback, long-winded for one look.
    private fun wifiNetwork(): Network? {
        fun isWifi(network: Network) =
            connectivity.getNetworkCapabilities(network)?.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) == true
        return connectivity.activeNetwork?.takeIf(::isWifi) ?: connectivity.allNetworks.firstOrNull(::isWifi)
    }

    private fun heard(network: Network, face: NetworkInterface, other: (InetAddress) -> Boolean): Boolean {
        val lock = wifi.createMulticastLock(TAG).apply { setReferenceCounted(false) }
        lock.acquire()
        try {
            MulticastSocket(null).use { socket ->
                // Next to the system's own multicast DNS socket on the same port.
                socket.reuseAddress = true
                socket.bind(InetSocketAddress(MDNS_PORT))
                network.bindSocket(socket)
                socket.joinGroup(InetSocketAddress(MDNS_GROUP, MDNS_PORT), face)
                socket.soTimeout = 500
                socket.send(DatagramPacket(SERVICES_QUERY, SERVICES_QUERY.size, MDNS_GROUP, MDNS_PORT))
                val packet = DatagramPacket(ByteArray(PACKET_SIZE), PACKET_SIZE)
                val until = System.nanoTime() + LISTEN_MS * 1_000_000
                while (System.nanoTime() < until) {
                    try {
                        socket.receive(packet)
                    } catch (_: SocketTimeoutException) {
                        continue
                    }
                    if (other(packet.address)) return true
                }
                return false
            }
        } catch (e: IOException) {
            if (BuildConfig.DEBUG) Log.w(TAG, "Wi-Fi check could not listen", e)
            return false
        } finally {
            lock.release()
        }
    }

    private companion object {
        const val TAG = "AirChat"
        const val MDNS_PORT = 5353
        const val LISTEN_MS = 6_000L
        const val PACKET_SIZE = 9_000
        val MDNS_GROUP: InetAddress = InetAddress.getByAddress(byteArrayOf(224.toByte(), 0, 0, 251.toByte()))

        /** "Which services are there?" (RFC 6763 §9): a PTR question for _services._dns-sd._udp.local. */
        val SERVICES_QUERY: ByteArray = run {
            val header = byteArrayOf(0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0)
            val name = listOf("_services", "_dns-sd", "_udp", "local")
                .flatMap { listOf(it.length.toByte()) + it.encodeToByteArray().toList() } + 0.toByte()
            header + name.toByteArray() + byteArrayOf(0, 12, 0, 1)
        }
    }
}
