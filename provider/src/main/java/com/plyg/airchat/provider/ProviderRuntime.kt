package com.plyg.airchat.provider

import android.Manifest
import android.app.Application
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageManager
import android.net.wifi.aware.WifiAwareManager
import android.os.Build
import android.util.Log
import androidx.core.content.ContextCompat
import androidx.core.content.edit
import com.plyg.airchat.core.Account
import com.plyg.airchat.core.openProvider
import com.plyg.airchat.net.AwareTransport
import com.plyg.airchat.net.ConnectionHub
import com.plyg.airchat.net.LanTransport
import com.plyg.airchat.net.Peer
import com.plyg.airchat.net.Transport
import com.plyg.airchat.net.TransportKind
import com.plyg.airchat.runtime.AirProvider
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.IOException

/**
 * The provider device (requirements AP-8): a node with no account, its keys made anew in memory
 * every start (rust/airchat-protocol/docs/protocol.md §5.2, §12), over Wi-Fi Aware and the local
 * network. It opens a mesh link to every AirChat device it sees (§10.2), passes envelopes on, and
 * carries paths as far as Air Provider mode allows (AP-5). Nothing of anyone is stored: the only
 * file it writes holds whether the user started it and the mode's switch. Main thread.
 */
class ProviderRuntime(private val app: Application) {
    data class State(
        val running: Boolean = false,
        /** AirChat devices it has links to now. */
        val neighbours: Int = 0,
        /** Paths it carries for others now. */
        val paths: Int = 0,
    )

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate)
    private val settings = app.getSharedPreferences(SETTINGS, Context.MODE_PRIVATE)
    val airProvider = AirProvider(app, settings)
    /** Without Wi-Fi Aware a provider is not offered (AP-1); the manifest requires it too. */
    val supported = app.packageManager.hasSystemFeature(PackageManager.FEATURE_WIFI_AWARE)
    private val aware: WifiAwareManager? = if (supported) app.getSystemService(WifiAwareManager::class.java) else null

    private var node: Account? = null
    private var hub: ConnectionHub? = null
    private val transports = mutableMapOf<TransportKind, Transport>()
    private val transportJobs = mutableMapOf<TransportKind, Job>()
    private val peersBy = mutableMapOf<TransportKind, List<Peer>>()
    private val jobs = mutableListOf<Job>()
    /** Devices this one is opening a link to. */
    private val connecting = mutableSetOf<Long>()

    private val _state = MutableStateFlow(State())
    val state: StateFlow<State> = _state

    /** Whether the user started it: it then starts again with the phone, until stopped. */
    var wanted: Boolean
        get() = settings.getBoolean(KEY_WANTED, false)
        set(value) = settings.edit { putBoolean(KEY_WANTED, value) }

    init {
        // Wi-Fi Aware comes and goes with Wi-Fi.
        val awareState = object : BroadcastReceiver() {
            override fun onReceive(context: Context, intent: Intent) {
                if (aware?.isAvailable == true) startTransports() else stopTransport(TransportKind.AWARE)
            }
        }
        ContextCompat.registerReceiver(
            app,
            awareState,
            IntentFilter(WifiAwareManager.ACTION_WIFI_AWARE_STATE_CHANGED),
            ContextCompat.RECEIVER_NOT_EXPORTED,
        )
    }

    /** What the user must grant before it can start. */
    fun missingPermissions(): List<String> {
        val needed = buildList {
            if (Build.VERSION.SDK_INT >= 37) add(Manifest.permission.ACCESS_LOCAL_NETWORK)
            if (Build.VERSION.SDK_INT >= 33) {
                add(Manifest.permission.NEARBY_WIFI_DEVICES)
                add(Manifest.permission.POST_NOTIFICATIONS)
            } else {
                add(Manifest.permission.ACCESS_FINE_LOCATION)
            }
        }
        return needed.filterNot { ContextCompat.checkSelfPermission(app, it) == PackageManager.PERMISSION_GRANTED }
    }

    fun start() {
        if (node != null || !supported) return
        val node = openProvider()
        val hub = ConnectionHub(node, scope, onClosed = { scope.launch { report() } })
        this.node = node
        this.hub = hub
        airProvider.setEnabled(true)
        jobs += scope.launch {
            airProvider.status.collect { status ->
                // Low battery or heat turned the mode off: on again once it can run (AP-5).
                if (!status.enabled && !status.cannotRun) airProvider.setEnabled(true)
                hub.perform { node.setAirProvider(status.classes) }
            }
        }
        // Transports that could not start, and devices seen but not reached, are tried again.
        jobs += scope.launch {
            while (true) {
                startTransports()
                connectToStrangers()
                delay(RECONNECT_INTERVAL_MS)
            }
        }
        // Links whose other end vanished without closing, paths gone quiet (§6.7, §12.3).
        jobs += scope.launch {
            while (true) {
                delay(TICK_INTERVAL_MS)
                withContext(Dispatchers.Default) { hub.perform { node.tick() } }
                report()
            }
        }
        _state.value = State(running = true)
    }

    fun stop() {
        jobs.forEach { it.cancel() }
        jobs.clear()
        transports.keys.toList().forEach(::stopTransport)
        hub?.closeAll()
        hub = null
        // The keys go with it: the next start makes new ones.
        node?.close()
        node = null
        connecting.clear()
        airProvider.setEnabled(false)
        _state.value = State()
    }

    private fun report() {
        val node = node ?: return
        _state.value = State(running = true, node.meshNeighbours().toInt(), node.pathsCarried().toInt())
    }

    private fun startTransports() {
        val (node, hub) = (node ?: return) to (hub ?: return)
        if (missingPermissions().isNotEmpty()) return
        startTransport(TransportKind.LAN) { LanTransport(app, hub, scope, node::presenceToken, { null }, { null }) }
        if (aware?.isAvailable == true) {
            startTransport(TransportKind.AWARE) { AwareTransport(app, hub, scope, node::presenceToken, { null }, { null }) }
        }
    }

    private fun startTransport(kind: TransportKind, create: () -> Transport) {
        if (kind in transports) return
        val transport = create()
        try {
            transport.start()
        } catch (e: Exception) {
            // IOException: unavailable right now; SecurityException: a permission was just revoked.
            if (e !is IOException && e !is SecurityException) throw e
            if (BuildConfig.DEBUG) Log.w(TAG, "$kind transport failed to start", e)
            transport.stop()
            return
        }
        transports[kind] = transport
        transportJobs[kind] = scope.launch {
            transport.peers.collect { peers ->
                peersBy[kind] = peers
                connectToStrangers()
            }
        }
    }

    private fun stopTransport(kind: TransportKind) {
        transportJobs.remove(kind)?.cancel()
        transports.remove(kind)?.stop()
        peersBy.remove(kind)
        hub?.closeConnections(kind)
    }

    /** Opens a mesh link to each device seen when it is this side's turn to (§10.2), LAN first. */
    private fun connectToStrangers() {
        val node = node ?: return
        val seen = mutableMapOf<Long, MutableList<Peer>>()
        for (peer in peersBy.values.flatten()) {
            val recognized = peer.presenceToken?.let(node::recognizeStranger) ?: continue
            if (recognized.initiate) seen.getOrPut(recognized.contactId) { mutableListOf() } += peer
        }
        for ((id, choices) in seen) {
            if (!connecting.add(id)) continue
            scope.launch { connect(id, choices.sortedBy { it.kind }) }
        }
    }

    /** Tries `choices` in order until one carries the first handshake message. */
    private suspend fun connect(id: Long, choices: List<Peer>) {
        val (node, hub) = (node ?: return) to (hub ?: return)
        try {
            for (peer in choices) {
                try {
                    withContext(Dispatchers.IO) {
                        val connection = hub.attach(peer.connect(), peer.kind)
                        hub.perform { node.connectContact(connection.toULong(), id) }
                    }
                    return
                } catch (e: Exception) {
                    if (e !is IOException && e !is SecurityException) throw e
                    if (BuildConfig.DEBUG) Log.w(TAG, "could not reach a device over ${peer.kind}", e)
                }
            }
        } finally {
            connecting.remove(id)
        }
    }

    private companion object {
        const val TAG = "AirChatProvider"
        const val SETTINGS = "provider"
        const val KEY_WANTED = "wanted"
        const val RECONNECT_INTERVAL_MS = 30_000L
        const val TICK_INTERVAL_MS = 5_000L
    }
}
