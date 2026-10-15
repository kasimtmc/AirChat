package com.plyg.airchat.net

import android.annotation.SuppressLint
import android.content.Context
import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.net.wifi.WifiManager
import android.net.wifi.WifiNetworkSpecifier
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.util.Log
import com.plyg.airchat.BuildConfig
import com.plyg.airchat.core.HotspotOffer
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withContext
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.net.Inet4Address
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException

/**
 * Fast Wi-Fi between two devices that share no network and lack Wi-Fi Aware (requirements T-6,
 * rust/airchat-protocol/docs/protocol.md §8.3). One device opens a local-only hotspot; the system picks a random name and
 * password, which reach the contact only over the encrypted link. The contact joins and opens a link
 * over it, which replaces the current one.
 *
 * Nothing names the phone: the network name is random, Android randomizes the hotspot's address, and
 * the joining phone uses a fresh random address for each new network. Android asks the joining user
 * to confirm, so this runs on demand only. One hotspot, hosted or joined, at a time. Main thread only.
 */
@SuppressLint("MissingPermission") // The runtime calls in only with the Wi-Fi permissions granted.
class HotspotLink(
    context: Context,
    private val hub: ConnectionHub,
    private val scope: CoroutineScope,
    /** The system stopped the hotspot this device opened (not when [close] did). */
    private val onHostStopped: () -> Unit,
) {
    private val wifi = context.getSystemService(WifiManager::class.java)
    private val connectivity = context.getSystemService(ConnectivityManager::class.java)
    private var reservation: WifiManager.LocalOnlyHotspotReservation? = null
    private var server: ServerSocket? = null
    private var joined: ConnectivityManager.NetworkCallback? = null

    val busy: Boolean get() = reservation != null || joined != null

    /** This device runs a hotspot now. */
    val hosting: Boolean get() = reservation != null

    /** Opens a hotspot and listens on it; returns what the contact needs to join it. */
    suspend fun host(): HotspotOffer {
        close()
        val reservation = suspendCancellableCoroutine { continuation ->
            wifi.startLocalOnlyHotspot(
                object : WifiManager.LocalOnlyHotspotCallback() {
                    override fun onStarted(reservation: WifiManager.LocalOnlyHotspotReservation) {
                        if (continuation.isActive) continuation.resume(reservation) else reservation.close()
                    }

                    override fun onFailed(reason: Int) {
                        if (continuation.isActive) {
                            continuation.resumeWithException(IOException("hotspot failed: $reason"))
                        } else {
                            // After starting: the system took the Wi-Fi chip for something else.
                            stoppedBySystem()
                        }
                    }

                    override fun onStopped() = stoppedBySystem()
                },
                Handler(Looper.getMainLooper()),
            )
        }
        this.reservation = reservation
        // A phone also connected to a router may move its new hotspot to the router's channel right
        // after starting it; a join attempted meanwhile finds nothing.
        delay(SETTLE_MS)
        if (this.reservation == null) throw IOException("the system stopped the hotspot at once")
        val (ssid, passphrase) = credentials(reservation)
        val socket = ServerSocket(0)
        server = socket
        scope.launch(Dispatchers.IO) {
            try {
                while (true) hub.attach(socket.accept().asStreamChannel(), TransportKind.HOTSPOT)
            } catch (_: IOException) {
                // Closed by close().
            }
        }
        return HotspotOffer(ssid, passphrase, socket.localPort.toUShort())
    }

    /**
     * Joins the contact's hotspot and connects to it at its gateway. Android first asks the user to
     * confirm; [IOException] if they decline or the network does not come up.
     */
    suspend fun join(offer: HotspotOffer): StreamChannel {
        close()
        // Fresh scan results let the system dialog find the new hotspot at once; without them it
        // sometimes searches its whole timeout in vain. Throttled by Android; best effort.
        @Suppress("DEPRECATION")
        if (runCatching { wifi.startScan() }.getOrDefault(false)) delay(SCAN_WAIT_MS)
        val specifier = WifiNetworkSpecifier.Builder()
            .setSsid(offer.ssid)
            .setWpa2Passphrase(offer.passphrase)
            .build()
        val request = NetworkRequest.Builder()
            .addTransportType(NetworkCapabilities.TRANSPORT_WIFI)
            .removeCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            .setNetworkSpecifier(specifier)
            .build()
        val network = suspendCancellableCoroutine { continuation ->
            val callback = object : ConnectivityManager.NetworkCallback() {
                override fun onAvailable(network: Network) {
                    if (continuation.isActive) continuation.resume(network)
                }

                override fun onUnavailable() {
                    if (continuation.isActive) continuation.resumeWithException(IOException("hotspot not joined"))
                }

                override fun onLost(network: Network) {
                    // The link over it ends by itself; the runtime falls back to another transport.
                    if (BuildConfig.DEBUG) Log.d(TAG, "the joined hotspot network was lost")
                }
            }
            joined = callback
            connectivity.requestNetwork(request, callback, JOIN_TIMEOUT_MS)
            // Withdrawn by the contact: stop asking (this also closes the system dialog).
            continuation.invokeOnCancellation { close() }
        }
        val gateway = gatewayOf(connectivity.getLinkProperties(network))
            ?: throw IOException("the hotspot gave no gateway").also { close() }
        val socket = network.socketFactory.createSocket()
        try {
            withContext(Dispatchers.IO) {
                socket.connect(InetSocketAddress(gateway, offer.port.toInt()), CONNECT_TIMEOUT_MS)
            }
        } catch (e: IOException) {
            socket.close()
            close()
            throw e
        }
        socket.forMedia()
        return object : StreamChannel {
            override val input: InputStream get() = socket.getInputStream()
            override val output: OutputStream get() = socket.getOutputStream()
            override fun close() = socket.close()
        }
    }

    private fun stoppedBySystem() {
        if (reservation == null) return
        if (BuildConfig.DEBUG) Log.d(TAG, "the system stopped the hotspot")
        close()
        onHostStopped()
    }

    /** Stops hosting or leaves the joined hotspot. */
    fun close() {
        runCatching { server?.close() }
        server = null
        reservation?.close()
        reservation = null
        joined?.let { runCatching { connectivity.unregisterNetworkCallback(it) } }
        joined = null
    }

    private fun credentials(reservation: WifiManager.LocalOnlyHotspotReservation): Pair<String, String> {
        if (Build.VERSION.SDK_INT >= 30) {
            val config = reservation.softApConfiguration
            val ssid = if (Build.VERSION.SDK_INT >= 33) config.wifiSsid?.toString() else @Suppress("DEPRECATION") config.ssid
            return unquote(checkNotNull(ssid)) to checkNotNull(config.passphrase)
        }
        @Suppress("DEPRECATION")
        val config = checkNotNull(reservation.wifiConfiguration)
        @Suppress("DEPRECATION")
        return unquote(config.SSID) to unquote(config.preSharedKey)
    }

    private companion object {
        /** The user has to notice and confirm the system dialog. */
        const val JOIN_TIMEOUT_MS = 120_000
        const val SETTLE_MS = 3_000L
        const val SCAN_WAIT_MS = 4_000L
        const val TAG = "AirChat"
        const val CONNECT_TIMEOUT_MS = 10_000

        fun unquote(value: String) = value.removeSurrounding("\"")

        /** The hotspot host is the network's gateway. */
        fun gatewayOf(properties: LinkProperties?): InetAddress? =
            properties?.routes?.firstOrNull { it.hasGateway() && it.gateway is Inet4Address }?.gateway
    }
}
