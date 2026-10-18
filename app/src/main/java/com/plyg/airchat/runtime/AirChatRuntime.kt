package com.plyg.airchat.runtime

import android.Manifest
import android.app.Application
import android.bluetooth.BluetoothAdapter
import android.bluetooth.BluetoothManager
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageManager
import android.net.wifi.aware.WifiAwareManager
import android.os.Build
import android.os.SystemClock
import android.util.Log
import androidx.core.content.ContextCompat
import androidx.core.content.edit
import com.plyg.airchat.BuildConfig
import com.plyg.airchat.security.BuildAttestation
import com.plyg.airchat.core.Account
import com.plyg.airchat.core.CoreException
import com.plyg.airchat.core.AttachmentState
import com.plyg.airchat.core.HotspotOffer
import com.plyg.airchat.core.MoveTarget
import com.plyg.airchat.core.PathClass
import com.plyg.airchat.core.Recognized
import com.plyg.airchat.net.AwareTransport
import com.plyg.airchat.net.BleTransport
import com.plyg.airchat.net.ConnectionHub
import com.plyg.airchat.net.HotspotLink
import com.plyg.airchat.net.LanTransport
import com.plyg.airchat.net.NetEvent
import com.plyg.airchat.net.Peer
import com.plyg.airchat.net.Transport
import com.plyg.airchat.net.TransportKind
import com.plyg.airchat.net.WifiCheck
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.IOException

/**
 * The account and the network, for as long as the process lives (docs/architecture.md §4.3). The UI
 * comes and goes; this stays, so a locked AirChat keeps its links and keeps receiving messages.
 *
 * - Unlocked: the account is open, the network runs, the UI may read everything.
 * - Locked ("sealed"): the database and its keys are gone from memory. Links stay up and incoming
 *   messages go to the encrypted inbox, if the user allows receiving while locked; otherwise locking
 *   closes everything.
 *
 * Main thread only, except where noted.
 */
class AirChatRuntime(private val app: Application) {
    val notifications = Notifications(app)
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate)
    /** Calls and push-to-talk; they go on in the background and while locked. */
    val voice = Voice(
        app,
        scope,
        notifications,
        onMicrophone = { microphone -> if (account != null) AirChatService.start(app, microphone) },
        linkOf = { contactId -> _linked.value[contactId] },
        carriesVideo = { contactId -> carriesVideo(contactId) },
        requestFastLink = { contactId -> requestFastLink(contactId, forCall = true) },
    )
    private val settings = app.getSharedPreferences(SETTINGS, Context.MODE_PRIVATE)
    /** Air Provider mode: what this device carries for others (requirements AP-1, AP-5). */
    val airProvider = AirProvider(app, settings)

    /** Open or sealed; null when nothing runs (never unlocked since start, or fully stopped). */
    var account: Account? = null
        private set
    var hub: ConnectionHub? = null
        private set
    private val transports = mutableMapOf<TransportKind, Transport>()
    private val transportJobs = mutableMapOf<TransportKind, Job>()
    private val peersBy = mutableMapOf<TransportKind, List<Peer>>()
    private val networkJobs = mutableListOf<Job>()
    /** Contacts this device is opening a connection to. */
    private val connecting = mutableSetOf<Long>()
    /** Contacts whose link could not be moved to a faster transport: no new attempt before then. */
    private val replaceBackoff = mutableMapOf<Long, Backoff>()

    private class Backoff(val failures: Int, val until: Long)
    /** Announced on every transport while "Add nearby" is open. */
    private var pairingToken: ByteArray? = null

    private val _peers = MutableStateFlow<List<Peer>>(emptyList())
    /** Every announcement heard on any transport. A device may appear once per transport. */
    val peers: StateFlow<List<Peer>> = _peers

    private val bluetooth: BluetoothAdapter? = app.getSystemService(BluetoothManager::class.java)?.adapter
    private val _bluetoothOn = MutableStateFlow(bluetooth?.isEnabled == true)
    val bluetoothOn: StateFlow<Boolean> = _bluetoothOn

    private val _events = MutableSharedFlow<NetEvent>(extraBufferCapacity = 64)
    /** Everything the network reports, for the UI. */
    val events: SharedFlow<NetEvent> = _events

    private val _meshNeighbours = MutableStateFlow(0)
    /** Links carrying mesh traffic now (rust/airchat-protocol/docs/protocol.md §10): other AirChat devices around, over Wi-Fi. */
    val meshNeighbours: StateFlow<Int> = _meshNeighbours

    private val _providers = MutableStateFlow(0)
    /** Air Providers among the mesh neighbours (rust/airchat-protocol/docs/protocol.md §12.1): paths can be looked for. */
    val providers: StateFlow<Int> = _providers

    private val _linked = MutableStateFlow<Map<Long, TransportKind>>(emptyMap())
    /** Contacts with an encrypted link up right now, and what carries it. */
    val linked: StateFlow<Map<Long, TransportKind>> = _linked

    private val _waitingForWifi = MutableStateFlow<Set<Long>>(emptySet())
    /** Contacts linked over Bluetooth only with messages waiting for Wi-Fi (rust/airchat-protocol/docs/protocol.md §7.3). */
    val waitingForWifi: StateFlow<Set<Long>> = _waitingForWifi

    private val _locked = MutableStateFlow(true)
    /** Whether the UI must show the lock screen: no account, or a sealed one. */
    val locked: StateFlow<Boolean> = _locked

    /**
     * The conversation on screen; its messages need no notification while the app is visible. The
     * notification names no conversation, so opening any one counts as having seen it.
     */
    var visibleChat: Long? = null
        set(value) {
            field = value
            if (value != null) notifications.clearMessages()
        }

    /** The same for the group whose conversation is on screen. */
    var visibleGroup: Long? = null
        set(value) {
            field = value
            if (value != null) notifications.clearMessages()
        }
    private var inForeground = false
    private var backgroundedAt: Long? = null
    private var lockTimer: Job? = null

    /**
     * Whether locking keeps links up so messages keep arriving (docs/architecture.md §4.3). Default on;
     * walkie-talkie listening will follow the same setting (requirement V-5).
     */
    var receiveWhileLocked: Boolean
        get() = settings.getBoolean(KEY_RECEIVE_WHILE_LOCKED, true)
        set(value) = settings.edit { putBoolean(KEY_RECEIVE_WHILE_LOCKED, value) }

    /** Whether people who typed this device's AirChat ID may ask to be added (requirement C-4). */
    var acceptRequests: Boolean
        get() = settings.getBoolean(KEY_ACCEPT_REQUESTS, true)
        set(value) {
            settings.edit { putBoolean(KEY_ACCEPT_REQUESTS, value) }
            // The core answers paths through Air Providers itself (§4.8).
            account?.setAcceptRequests(value)
        }

    /** Whether the permissions were asked for once after the first unlock. */
    var askedForPermissions: Boolean
        get() = settings.getBoolean(KEY_ASKED_FOR_PERMISSIONS, false)
        set(value) = settings.edit { putBoolean(KEY_ASKED_FOR_PERMISSIONS, value) }

    init {
        // A sleeping CPU does not run the auto-lock timer; check again as soon as the screen wakes.
        val screen = object : BroadcastReceiver() {
            override fun onReceive(context: Context, intent: Intent) = lockIfIdle()
        }
        ContextCompat.registerReceiver(
            app,
            screen,
            IntentFilter(Intent.ACTION_SCREEN_ON),
            ContextCompat.RECEIVER_NOT_EXPORTED,
        )
        val bluetoothState = object : BroadcastReceiver() {
            override fun onReceive(context: Context, intent: Intent) {
                when (intent.getIntExtra(BluetoothAdapter.EXTRA_STATE, BluetoothAdapter.ERROR)) {
                    BluetoothAdapter.STATE_ON -> {
                        _bluetoothOn.value = true
                        startNetwork()
                    }
                    BluetoothAdapter.STATE_TURNING_OFF, BluetoothAdapter.STATE_OFF -> {
                        _bluetoothOn.value = false
                        stopTransport(TransportKind.BLE)
                    }
                }
            }
        }
        ContextCompat.registerReceiver(
            app,
            bluetoothState,
            IntentFilter(BluetoothAdapter.ACTION_STATE_CHANGED),
            ContextCompat.RECEIVER_NOT_EXPORTED,
        )
        // Wi-Fi Aware comes and goes with Wi-Fi, location (before Android 13) and hotspot use.
        val awareState = object : BroadcastReceiver() {
            override fun onReceive(context: Context, intent: Intent) {
                if (awareAvailable()) startNetwork() else stopTransport(TransportKind.AWARE)
            }
        }
        ContextCompat.registerReceiver(
            app,
            awareState,
            IntentFilter(WifiAwareManager.ACTION_WIFI_AWARE_STATE_CHANGED),
            ContextCompat.RECEIVER_NOT_EXPORTED,
        )
    }

    /** Takes over an account the user just unlocked from scratch. */
    fun start(unlocked: Account) {
        stop()
        account = unlocked
        unlocked.setAcceptRequests(acceptRequests)
        _locked.value = false
        notifications.clearMessages()
        startNetwork()
        AirChatService.start(app)
    }

    /**
     * The sealed account was unlocked again. What arrived meanwhile is in the database now; the UI
     * reads it from there, so the core's report of it is not passed on (it would only notify).
     */
    fun unsealed() {
        _locked.value = false
        notifications.clearMessages()
    }

    /** Locks the account. Callers then show the lock screen. */
    fun lock() {
        val account = account ?: return
        lockTimer?.cancel()
        if (!receiveWhileLocked) return stop()
        if (account.isLocked()) return
        setPairingToken(null)
        val hub = hub
        if (hub != null) hub.perform { account.seal() } else account.seal()
        _locked.value = true
    }

    /** Closes the account and the network, e.g. before the account is reset. */
    fun stop() {
        lockTimer?.cancel()
        stopNetwork()
        account?.close()
        account = null
        _locked.value = true
        AirChatService.stop(app)
    }

    // Foreground and background.

    fun onForeground() {
        inForeground = true
        lockIfIdle()
        backgroundedAt = null
        lockTimer?.cancel()
        if (!_locked.value) notifications.clearMessages()
        refreshTransports()
    }

    private var refreshedAt = 0L

    /** Restarts discovery that the platform may have stopped while the app was in the background. */
    private fun refreshTransports() {
        val now = SystemClock.elapsedRealtime()
        if (now - refreshedAt < REFRESH_MIN_INTERVAL_MS) return
        refreshedAt = now
        transports.values.forEach { it.refresh() }
    }

    fun onBackground() {
        inForeground = false
        backgroundedAt = SystemClock.elapsedRealtime()
        lockTimer?.cancel()
        lockTimer = scope.launch {
            delay(AUTO_LOCK_AFTER_MS)
            // Not in the middle of a call or talk: once it is over.
            while (voice.busy) delay(BUSY_RECHECK_MS)
            lock()
        }
    }

    private fun lockIfIdle() {
        val since = backgroundedAt ?: return
        if (SystemClock.elapsedRealtime() - since >= AUTO_LOCK_AFTER_MS && !voice.busy) lock()
    }

    // Permissions.

    /** Android 17 asks the user before an app may use the local network. */
    private fun networkPermissions(): List<String> =
        if (Build.VERSION.SDK_INT >= 37) listOf(Manifest.permission.ACCESS_LOCAL_NETWORK) else emptyList()

    private fun bluetoothPermissions(): List<String> = if (Build.VERSION.SDK_INT >= 31) {
        listOf(
            Manifest.permission.BLUETOOTH_SCAN,
            Manifest.permission.BLUETOOTH_ADVERTISE,
            Manifest.permission.BLUETOOTH_CONNECT,
        )
    } else {
        // Android 10 and 11 deliver BLE scan results only to apps with location access.
        listOf(Manifest.permission.ACCESS_FINE_LOCATION)
    }

    /** Wi-Fi Aware and hotspots: "nearby Wi-Fi devices" from Android 13, location access before. */
    private fun wifiPermissions(): List<String> = if (Build.VERSION.SDK_INT >= 33) {
        listOf(Manifest.permission.NEARBY_WIFI_DEVICES)
    } else {
        listOf(Manifest.permission.ACCESS_FINE_LOCATION, Manifest.permission.ACCESS_COARSE_LOCATION)
    }

    fun networkPermitted(): Boolean = networkPermissions().all(::granted)

    fun bluetoothPermitted(): Boolean = bluetoothPermissions().all(::granted)

    fun wifiPermitted(): Boolean = wifiPermissions().all(::granted)

    /** What the transports need and the user has not granted. */
    fun missingTransportPermissions(): List<String> =
        (networkPermissions() + bluetoothPermissions() + wifiPermissions()).distinct().filterNot(::granted)

    private val aware: WifiAwareManager? =
        if (app.packageManager.hasSystemFeature(PackageManager.FEATURE_WIFI_AWARE)) {
            app.getSystemService(WifiAwareManager::class.java)
        } else {
            null
        }

    private fun awareAvailable() = aware?.isAvailable == true

    private fun granted(permission: String) =
        ContextCompat.checkSelfPermission(app, permission) == PackageManager.PERMISSION_GRANTED

    // Networking.

    // Verified builds (rust/airchat-protocol/docs/protocol.md §6.10).

    /** The challenge this account's attestation carries, once it has one. */
    @Volatile private var attestationChallenge: ByteArray? = null

    /** Makes (once) this phone's attestation of the account and gives it to the core. */
    private fun attestBuild(account: Account, hub: ConnectionHub) {
        try {
            // Debug builds are signed with a key of their own: they test verified builds with it.
            if (BuildConfig.DEBUG) BuildAttestation.ownSigner(app)?.let(account::trustSigner)
            val challenge = account.attestationChallenge()
            val chain = BuildAttestation.chain(challenge) ?: return
            attestationChallenge = challenge
            hub.perform { account.setAttestation(chain) }
        } catch (e: CoreException) {
            if (BuildConfig.DEBUG) Log.d(TAG, "no attestation: $e")
        }
    }

    /** Signs a link for the attestation and sends it to the contact. */
    private fun proveBuild(contact: Long, message: ByteArray) {
        val (account, hub) = (account ?: return) to (hub ?: return)
        val challenge = attestationChallenge ?: return
        val proof = BuildAttestation.sign(challenge, message) ?: return
        try {
            hub.perform { account.sendAttestation(contact, proof) }
        } catch (_: CoreException) {
        }
    }

    /** Whether any transport runs, so that "Add nearby" can find someone. */
    val canDiscover: Boolean get() = transports.isNotEmpty()

    /** Starts whatever part of the network is not running and may run now. */
    fun startNetwork() {
        val account = account ?: return
        val hub = hub ?: ConnectionHub(
            account,
            scope,
            onClosed = { kind -> scope.launch { connectionClosed(kind) } },
            onAudio = voice::onAudio,
            onVideo = voice::onVideo,
            onAttestationWanted = { contact, message -> scope.launch(Dispatchers.Default) { proveBuild(contact, message) } },
        ).also { hub ->
            this.hub = hub
            voice.account = account
            voice.hub = hub
            hotspot = HotspotLink(app, hub, scope, onHostStopped = ::hotspotStopped)
            networkJobs += scope.launch { hub.events.collect(::onNetEvent) }
            networkJobs += scope.launch(Dispatchers.Default) { attestBuild(account, hub) }
            networkJobs += scope.launch { _peers.collect(::connectToContacts) }
            // Retry contacts that were seen but could not be reached, and transports that could not
            // start (e.g. Bluetooth was not ready yet right after it was turned on).
            networkJobs += scope.launch {
                while (true) {
                    delay(RECONNECT_INTERVAL_MS)
                    startNetwork()
                    connectToContacts(_peers.value)
                    leaveQuietHotspots()
                }
            }
            // Notice links whose other end vanished without closing (rust/airchat-protocol/docs/protocol.md §6.7).
            networkJobs += scope.launch {
                while (true) {
                    delay(TICK_INTERVAL_MS)
                    withContext(Dispatchers.Default) { hub.perform { account.tick() } }
                    // Neighbours say what they carry in records of their own, not in events.
                    _providers.value = account.providers(PathClass.VOICE).toInt()
                }
            }
            networkJobs += scope.launch {
                airProvider.status.collect { status -> hub.perform { account.setAirProvider(status.classes) } }
            }
        }
        startTransport(TransportKind.LAN, networkPermitted()) {
            LanTransport(app, hub, scope, account::presenceToken, account::channelToken, ::requestToken)
        }
        // Many Wi-Fi chips run Wi-Fi Aware or a hotspot, not both: attaching to Aware would stop it.
        startTransport(TransportKind.AWARE, wifiPermitted() && awareAvailable() && hotspot?.hosting != true) {
            AwareTransport(app, hub, scope, account::presenceToken, account::channelToken, ::requestToken)
        }
        startTransport(TransportKind.BLE, bluetoothPermitted() && _bluetoothOn.value) {
            BleTransport(app, hub, scope, account::presenceToken, account::channelToken, ::requestToken)
        }
    }

    private fun startTransport(kind: TransportKind, allowed: Boolean, create: () -> Transport) {
        if (!allowed || kind in transports || !transportEnabled(kind)) return
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
        debug { "$kind transport started" }
        transportJobs[kind] = scope.launch {
            transport.peers.collect { peers ->
                peersBy[kind] = peers
                _peers.value = peersBy.values.flatten()
            }
        }
        pairingToken?.let(transport::setPairingToken)
    }

    private fun stopTransport(kind: TransportKind) {
        transportJobs.remove(kind)?.cancel()
        transports.remove(kind)?.stop()
        hub?.closeConnections(kind)
        peersBy.remove(kind)
        _peers.value = peersBy.values.flatten()
    }

    private fun stopNetwork() {
        networkJobs.forEach { it.cancel() }
        networkJobs.clear()
        transports.keys.toList().forEach(::stopTransport)
        hotspot?.close()
        hotspot = null
        hostingFor = null
        fastLinkForDownloads.clear()
        fastLinkForCalls.clear()
        fastLinkForMessages.clear()
        _waitingForWifi.value = emptySet()
        _meshNeighbours.value = 0
        _providers.value = 0
        hub?.closeAll()
        hub = null
        voice.stopAll()
        voice.hub = null
        voice.account = null
        pairingToken = null
        connecting.clear()
        replaceBackoff.clear()
        _linked.value = emptyMap()
    }

    // Fast Wi-Fi on demand (requirements T-6, rust/airchat-protocol/docs/protocol.md §8.3).

    private var hotspot: HotspotLink? = null
    /** The contact a hotspot is open for, until their connection arrives or the wait times out. */
    private var hostingFor: Long? = null

    /** Contacts whose link was moved to a hotspot for downloads; it is let go once they are done. */
    private val fastLinkForDownloads = mutableSetOf<Long>()
    /** Contacts whose link was moved to a hotspot for a video call; it is let go after the call. */
    private val fastLinkForCalls = mutableSetOf<Long>()
    /**
     * Contacts whose link was moved to a hotspot for messages, with when a message last went either
     * way ([SystemClock.elapsedRealtime]); it is let go once the conversation has been quiet a while.
     */
    private val fastLinkForMessages = mutableMapOf<Long, Long>()
    /** When this device last asked each contact for a hotspot ([SystemClock.elapsedRealtime]). */
    private val askedForHotspotAt = mutableMapOf<Long, Long>()

    init {
        airProvider.onStoppedItself = notifications::airProviderStopped
        // Here, after what they use: the main-thread scope runs them at once.
        scope.launch { _locked.collect { voice.setUnlocked(!it) } }
        // A link moved to a hotspot for a video call goes back once the call is over.
        scope.launch {
            voice.call.collect { call ->
                if (call == null || call.phase == CallPhase.ENDED) fastLinkForCalls.toList().forEach(::callEnded)
            }
        }
    }

    /**
     * Moves the link with a contact to fast Wi-Fi, e.g. before a large transfer: the contact opens a
     * hotspot and this device joins it, after the user confirms. Nothing to do if the link already
     * runs over Wi-Fi. With [forDownloads], this device leaves the hotspot again once no download
     * from the contact is under way; with [forCall], once the call is over. Returns whether a move
     * was asked for.
     */
    fun requestFastLink(
        contactId: Long,
        forDownloads: Boolean = false,
        forCall: Boolean = false,
        forMessages: Boolean = false,
    ): Boolean {
        val (account, hub) = (account ?: return false) to (hub ?: return false)
        val current = _linked.value[contactId] ?: return false
        // A contact reached through Air Providers is out of reach of a hotspot: a path that
        // carries video instead (rust/airchat-protocol/docs/protocol.md §12).
        if (current == TransportKind.RELAY) return forCall && findPath(contactId, PathClass.VIDEO)
        if (current <= TransportKind.HOTSPOT || !wifiPermitted() || hotspot?.busy == true) return false
        return try {
            hub.perform { account.requestMove(contactId, MoveTarget.HOTSPOT) }
            askedForHotspotAt[contactId] = SystemClock.elapsedRealtime()
            debug { "asked contact $contactId to open a hotspot" }
            if (forDownloads) fastLinkForDownloads += contactId
            if (forCall) fastLinkForCalls += contactId
            if (forMessages) fastLinkForMessages[contactId] = SystemClock.elapsedRealtime()
            true
        } catch (_: CoreException) {
            false
        }
    }

    // Paths through Air Providers (rust/airchat-protocol/docs/protocol.md §12, requirements AP-7).

    /**
     * Looks for a path through Air Providers to a contact no direct Wi-Fi link reaches, one that
     * carries [pathClass]. A link over it comes up ([NetEvent.LinkUp] over [TransportKind.RELAY]),
     * or [NetEvent.PathFailed] follows. False if no neighbour carries that.
     */
    fun findPath(contactId: Long, pathClass: PathClass): Boolean {
        val (account, hub) = (account ?: return false) to (hub ?: return false)
        return try {
            hub.perform { account.findPath(contactId, pathClass) }
            debug { "looking for a $pathClass path to contact $contactId" }
            true
        } catch (_: CoreException) {
            false
        }
    }

    /**
     * Looks for paths through Air Providers to the members of a group no link reaches now
     * (rust/airchat-protocol/docs/protocol.md §9.6). False if no neighbour carries voice.
     */
    fun reachGroup(groupId: Long): Boolean {
        val (account, hub) = (account ?: return false) to (hub ?: return false)
        if (providers(PathClass.VOICE) == 0) return false
        return try {
            hub.perform { account.reachGroup(groupId) }
            true
        } catch (_: CoreException) {
            false
        }
    }

    /** Looks for a member of the tuned walkie-talkie channel through Air Providers (§11.5). */
    fun findChannelPath(): Boolean {
        val (account, hub) = (account ?: return false) to (hub ?: return false)
        if (providers(PathClass.VOICE) == 0) return false
        return try {
            hub.perform { account.findChannelPath() }
            true
        } catch (_: CoreException) {
            false
        }
    }

    /** Neighbours that carry [pathClass] for others now. */
    /** The Wi-Fi check (requirements AP-10): whether devices on this Wi-Fi reach each other. */
    suspend fun checkWifi(): WifiCheck.Result = WifiCheck(app).run(linkedOverWifi = hub?.carries(TransportKind.LAN) == true)

    fun providers(pathClass: PathClass): Int = account?.providers(pathClass)?.toInt() ?: 0

    /** Whether the link to a contact may carry video: Wi-Fi, or a path that carries it. */
    fun carriesVideo(contactId: Long): Boolean = when (_linked.value[contactId]) {
        null, TransportKind.BLE -> false
        TransportKind.RELAY -> account?.linkPath(contactId)?.pathClass == PathClass.VIDEO
        else -> true
    }

    /** The call the link to a contact was moved for is over: leave the hotspot, unless something else needs it. */
    private fun callEnded(contactId: Long) {
        if (!fastLinkForCalls.remove(contactId) || contactId in fastLinkForDownloads || contactId in fastLinkForMessages) return
        if (_linked.value[contactId] == TransportKind.HOTSPOT) {
            debug { "video call with contact $contactId over: leaving the hotspot" }
            hub?.closeConnections(TransportKind.HOTSPOT)
        }
    }

    /**
     * Leaves hotspots joined for messages once the conversation has been quiet for a while: no
     * message either way, and no file's chunks (the contact may be fetching one from this device).
     */
    private fun leaveQuietHotspots() {
        val now = SystemClock.elapsedRealtime()
        val quiet = fastLinkForMessages
            .filter { (contactId, at) -> now - at >= MESSAGES_QUIET_MS && hub?.carriedBulk(contactId, MESSAGES_QUIET_MS) != true }
            .keys
        for (contactId in quiet) {
            fastLinkForMessages.remove(contactId)
            if (contactId in fastLinkForCalls || contactId in fastLinkForDownloads) continue
            if (_linked.value[contactId] == TransportKind.HOTSPOT) {
                debug { "conversation with contact $contactId quiet: leaving the hotspot" }
                hub?.closeConnections(TransportKind.HOTSPOT)
            }
        }
    }

    /** A message went either way: a hotspot joined for messages stays a while longer. */
    private fun messageActivity(contactId: Long) {
        fastLinkForMessages.computeIfPresent(contactId) { _, _ -> SystemClock.elapsedRealtime() }
    }

    /** A file from a contact arrived or failed: leave their hotspot if it was joined for downloads now over. */
    private fun downloadEnded(contactId: Long) {
        if (contactId !in fastLinkForDownloads) return
        val account = account ?: return
        scope.launch {
            val fetching = withContext(Dispatchers.Default) {
                try {
                    account.messages(contactId).any { !it.outgoing && it.attachment?.state == AttachmentState.DOWNLOADING }
                } catch (_: CoreException) {
                    true
                }
            }
            if (fetching || !fastLinkForDownloads.remove(contactId)) return@launch
            if (contactId in fastLinkForCalls || contactId in fastLinkForMessages) return@launch
            if (_linked.value[contactId] == TransportKind.HOTSPOT) {
                debug { "downloads from contact $contactId done: leaving the hotspot" }
                // The link falls back to whatever else reaches the contact.
                hub?.closeConnections(TransportKind.HOTSPOT)
            }
        }
    }

    /** The contact asks for a hotspot: open one, or say no. */
    private fun hostHotspot(contactId: Long) {
        val (account, hub, hotspot) = Triple(account ?: return, hub ?: return, hotspot ?: return)
        scope.launch {
            val offer = if (wifiPermitted() && !hotspot.busy) {
                // Many chips run Wi-Fi Aware or a hotspot, not both: let the hotspot have the chip.
                stopTransport(TransportKind.AWARE)
                try {
                    hotspot.host()
                } catch (e: Exception) {
                    if (e !is IOException && e !is SecurityException && e !is IllegalStateException) throw e
                    if (BuildConfig.DEBUG) Log.w(TAG, "could not open a hotspot", e)
                    null
                }
            } else {
                null
            }
            try {
                if (offer == null) {
                    startNetwork()
                    hub.perform { account.declineMove(contactId, MoveTarget.HOTSPOT) }
                    hostingFailed(contactId)
                    return@launch
                }
                hub.perform { account.offerHotspot(contactId, offer) }
                hostingFor = contactId
                debug { "hotspot open for contact $contactId" }
                // Close it again if the contact never comes.
                delay(HOTSPOT_WAIT_MS)
                if (hostingFor == contactId && !hub.carries(TransportKind.HOTSPOT)) closeHotspot()
            } catch (_: CoreException) {
                closeHotspot()
            }
        }
    }

    /** The system stopped the hotspot this device opened, e.g. to use its Wi-Fi chip otherwise. */
    private fun hotspotStopped() {
        startNetwork()
        val contactId = hostingFor ?: return
        hostingFor = null
        debug { "the system stopped our hotspot" }
        // A connection over it ends by itself; a contact still on the way is told not to wait.
        val (account, hub) = (account ?: return) to (hub ?: return)
        if (hub.carries(TransportKind.HOTSPOT)) return
        try {
            hub.perform { account.declineMove(contactId, MoveTarget.HOTSPOT) }
        } catch (_: CoreException) {
            // No link any more: nobody to tell.
        }
        hostingFailed(contactId)
    }

    /**
     * This device could not keep the hotspot a contact asked for: some phones lose it within
     * seconds (the Xiaomi, docs/architecture.md §5) where the contact's would hold. Ask it to open
     * one instead, unless this device asked it first (no asking back and forth), and stay on it for
     * the call with the contact, else while messages or files flow.
     */
    private fun hostingFailed(contactId: Long) {
        val asked = askedForHotspotAt[contactId]
        if (asked != null && SystemClock.elapsedRealtime() - asked < ASK_BACK_AFTER_MS) return
        val call = voice.call.value
        val inCall = call != null && call.contactId == contactId && call.groupId == null && call.phase != CallPhase.ENDED
        debug { "could not host for contact $contactId: asking it to host" }
        requestFastLink(contactId, forCall = inCall, forMessages = !inCall)
    }

    /** Joining the contact's hotspot, until the link moves there or the contact withdraws it. */
    private var joining: Job? = null

    /** The contact opened a hotspot for this device: join it and move the link there. */
    private fun joinHotspot(contactId: Long, offer: HotspotOffer) {
        val (account, hub, hotspot) = Triple(account ?: return, hub ?: return, hotspot ?: return)
        joining?.cancel()
        joining = scope.launch {
            try {
                val stream = hotspot.join(offer)
                withContext(Dispatchers.IO) {
                    val connection = hub.attach(stream, TransportKind.HOTSPOT)
                    hub.perform { account.connectContact(connection.toULong(), contactId) }
                }
            } catch (e: Exception) {
                if (e !is IOException && e !is SecurityException && e !is CoreException) throw e
                if (BuildConfig.DEBUG) Log.w(TAG, "could not join the hotspot of contact $contactId", e)
                closeHotspot()
            }
        }
    }

    private fun closeHotspot() {
        hotspot?.close()
        hostingFor = null
        // Wi-Fi Aware may run again.
        startNetwork()
    }

    /** A connection ended: let go of a hotspot nothing uses any more. */
    private fun connectionClosed(kind: TransportKind) {
        if (kind == TransportKind.HOTSPOT) debug { "a hotspot connection closed" }
        if (kind == TransportKind.HOTSPOT && hub?.carries(TransportKind.HOTSPOT) == false) {
            debug { "hotspot no longer used" }
            closeHotspot()
        }
    }

    /** A contact was blocked, unblocked or deleted: link to whoever may be linked now, at once. */
    fun contactsChanged() = connectToContacts(_peers.value)

    /** The tuned walkie-talkie channel changed: announce it now, and link with its members around. */
    fun channelChanged() {
        transports.values.forEach { it.channelChanged() }
        connectToContacts(_peers.value)
    }

    /**
     * The request to announce (rust/airchat-protocol/docs/protocol.md §4.8): one at a time, the IDs typed taking turns
     * each minute; none while locked.
     */
    private fun requestToken(): ByteArray? {
        val tokens = account?.requestTokens().orEmpty()
        if (tokens.isEmpty()) return null
        return tokens[((System.currentTimeMillis() / 60_000L) % tokens.size).toInt()]
    }

    /** The user typed an ID or withdrew one: announce the change now rather than within a minute. */
    fun requestsChanged() {
        transports.values.forEach { it.requestChanged() }
    }

    /** Answers a request for this device's owner, seen nearby, on a connection of its own. */
    private fun answerRequest(peer: Peer, token: ByteArray) {
        val (account, hub) = (account ?: return) to (hub ?: return)
        scope.launch {
            try {
                withContext(Dispatchers.IO) {
                    val connection = hub.attach(peer.connect(), peer.kind)
                    hub.perform { account.answerRequest(connection.toULong(), token) }
                }
            } catch (e: Exception) {
                if (e !is IOException && e !is SecurityException && e !is CoreException) throw e
                if (BuildConfig.DEBUG) Log.w(TAG, "could not answer a contact request over ${peer.kind}", e)
            }
        }
    }

    /** Announces the pairing token on every transport while "Add nearby" is open; `null` withdraws it. */
    fun setPairingToken(token: ByteArray?) {
        pairingToken = token
        transports.values.forEach { it.setPairingToken(token) }
    }

    /**
     * Debug builds only: a transport can be switched off to test the others on their own. Switching
     * one off also ends the links it carries.
     */
    fun transportEnabled(kind: TransportKind): Boolean =
        !BuildConfig.DEBUG || settings.getBoolean(KEY_TRANSPORT_PREFIX + kind.name, true)

    fun setTransportEnabled(kind: TransportKind, enabled: Boolean) {
        if (!BuildConfig.DEBUG) return
        settings.edit { putBoolean(KEY_TRANSPORT_PREFIX + kind.name, enabled) }
        if (enabled) startNetwork() else stopTransport(kind)
    }

    /**
     * Debug builds only: off, this device opens no links to contacts or members of its tuned
     * channel, so two of them that both switch it off reach each other only through Air Providers
     * (to test paths, §11.5, §12); nor does it answer requests to add seen nearby, which then come
     * only over paths (§4.8).
     */
    val directContactLinks: Boolean
        get() = !BuildConfig.DEBUG || settings.getBoolean(KEY_DIRECT_CONTACT_LINKS, true)

    fun setDirectContactLinks(enabled: Boolean) {
        if (!BuildConfig.DEBUG) return
        settings.edit { putBoolean(KEY_DIRECT_CONTACT_LINKS, enabled) }
        // Links up now go; the network comes back without them.
        stopNetwork()
        startNetwork()
    }

    /**
     * Opens links to contacts seen on the network when it is this device's turn to (§5.2), over the
     * preferred transport that sees them. A link already up over a slower transport is moved: a new
     * link over the faster one replaces it once it is up (docs/architecture.md §5).
     */
    private fun connectToContacts(peers: List<Peer>) {
        val (account, hub) = (account ?: return) to (hub ?: return)
        debug { "peers: " + peers.groupingBy { it.kind }.eachCount() }
        val seen = mutableMapOf<Long, Pair<Recognized, MutableList<Peer>>>()
        // Requests for this device's owner (§4.8); the core answers each token once a minute at most,
        // none while locked and none while the user turned requests off.
        for (peer in peers) {
            if (!directContactLinks) break
            val token = peer.requestToken ?: continue
            if (account.recognizeRequest(token)) answerRequest(peer, token)
        }
        for (peer in peers) {
            // Contacts by their presence token; members of the tuned channel by its token (§11.2);
            // any other AirChat device heard over Wi-Fi, for the mesh (§10.2).
            val contact = peer.presenceToken?.let(account::recognizePresence)
            if (contact != null && !directContactLinks) continue
            val member = if (contact == null) peer.channelToken?.let(account::recognizeChannel) else null
            if (member != null && !directContactLinks) continue
            val recognized = contact
                ?: member
                ?: peer.presenceToken?.takeIf { peer.kind != TransportKind.BLE }?.let(account::recognizeStranger)
                ?: continue
            seen.getOrPut(recognized.contactId) { recognized to mutableListOf() }.second += peer
        }
        val now = SystemClock.elapsedRealtime()
        for ((contactId, entry) in seen) {
            val (recognized, candidates) = entry
            var choices = candidates.sortedBy { it.kind }
            when {
                recognized.initiate -> Unit
                recognized.mayReplace -> {
                    val current = recognized.linkConnection?.let { hub.kindOf(it.toLong()) } ?: continue
                    choices = choices.filter { it.kind < current }
                    if (choices.isEmpty() || now < (replaceBackoff[contactId]?.until ?: 0)) continue
                    debug { "moving the link to contact $contactId from $current to ${choices.first().kind}" }
                }
                else -> continue
            }
            if (!connecting.add(contactId)) continue
            scope.launch { connect(contactId, choices, replacing = !recognized.initiate) }
        }
    }

    /** Tries `choices` in order until one carries the first handshake message. */
    private suspend fun connect(contactId: Long, choices: List<Peer>, replacing: Boolean) {
        val (account, hub) = (account ?: return) to (hub ?: return)
        try {
            for (peer in choices) {
                try {
                    withContext(Dispatchers.IO) {
                        val connection = hub.attach(peer.connect(), peer.kind)
                        hub.perform { account.connectContact(connection.toULong(), contactId) }
                    }
                    return
                } catch (e: Exception) {
                    if (e !is IOException && e !is SecurityException) throw e
                    if (BuildConfig.DEBUG) Log.w(TAG, "could not reach contact $contactId over ${peer.kind}", e)
                }
            }
            // The old link still works; try the faster transport again later, less and less often.
            if (replacing) {
                val failures = (replaceBackoff[contactId]?.failures ?: 0) + 1
                val wait = minOf(REPLACE_RETRY_MS shl minOf(failures - 1, 4), REPLACE_RETRY_MAX_MS)
                replaceBackoff[contactId] = Backoff(failures, SystemClock.elapsedRealtime() + wait)
            }
        } finally {
            connecting.remove(contactId)
        }
    }

    private fun onNetEvent(event: NetEvent) {
        voice.onEvent(event)
        when (event) {
            is NetEvent.LinkUp -> {
                debug { "link to contact ${event.contactId} up over ${event.via}" }
                _meshNeighbours.value = account?.meshNeighbours()?.toInt() ?: 0
                _linked.value += event.contactId to event.via
                replaceBackoff.remove(event.contactId)
                // Over Wi-Fi, what waited went out.
                if (event.via != TransportKind.BLE) _waitingForWifi.value -= event.contactId
            }
            is NetEvent.WaitingForWifi -> _waitingForWifi.value += event.contactId
            is NetEvent.PathFailed -> debug { "no path to contact ${event.contactId}" }
            is NetEvent.LinkDown -> {
                _meshNeighbours.value = account?.meshNeighbours()?.toInt() ?: 0
                _waitingForWifi.value -= event.contactId
                _linked.value -= event.contactId
                // Reconnect at once, over whatever still sees the contact, rather than at the next retry.
                connectToContacts(_peers.value)
            }
            // Only ever arrive while locked: the message went to the inbox. Muted ones notify nothing.
            is NetEvent.MessageArrived -> if (!muted(contactId = event.contactId)) notifications.newMessage()
            is NetEvent.GroupMessageArrived ->
                if (event.groupId?.let { muted(groupId = it) } != true) notifications.newMessage()
            is NetEvent.MoveRequested -> when (event.target) {
                MoveTarget.HOTSPOT -> hostHotspot(event.contactId)
            }
            is NetEvent.HotspotOffered -> joinHotspot(event.contactId, event.offer)
            is NetEvent.ContactRequested -> if (!inForeground || _locked.value) notifications.contactRequest()
            is NetEvent.MoveDeclined -> {
                debug { "contact ${event.contactId} could not open a hotspot, or stopped it" }
                if (joining?.isActive == true) {
                    joining?.cancel()
                    closeHotspot()
                }
            }
            is NetEvent.MessageReceived -> {
                messageActivity(event.message.contactId)
                if ((!inForeground || _locked.value || visibleChat != event.message.contactId) &&
                    !muted(contactId = event.message.contactId)
                ) {
                    notifications.newMessage()
                }
            }
            is NetEvent.GroupMessageReceived -> if (
                (!inForeground || _locked.value || visibleGroup != event.message.groupId) &&
                !muted(groupId = event.message.groupId)
            ) {
                notifications.newMessage()
            }
            is NetEvent.MessageUpdated -> {
                messageActivity(event.message.contactId)
                val state = event.message.attachment?.state
                if (!event.message.outgoing && state != null && state != AttachmentState.DOWNLOADING && state != AttachmentState.OFFERED) {
                    downloadEnded(event.message.contactId)
                }
            }
            else -> Unit
        }
        _events.tryEmit(event)
    }

    /** Whether the user muted a contact or a group (docs/architecture.md §4.7); known while locked too. */
    private fun muted(contactId: Long? = null, groupId: Long? = null): Boolean {
        val account = account ?: return false
        return (contactId != null && account.contactMuted(contactId)) || (groupId != null && account.groupMuted(groupId))
    }

    /** Debug builds only, and never with message content or names. */
    private inline fun debug(message: () -> String) {
        if (BuildConfig.DEBUG) Log.d(TAG, message())
    }

    private companion object {
        const val TAG = "AirChat"
        const val SETTINGS = "settings"
        const val KEY_RECEIVE_WHILE_LOCKED = "receive_while_locked"
        const val KEY_ACCEPT_REQUESTS = "accept_requests"
        const val KEY_ASKED_FOR_PERMISSIONS = "asked_for_permissions"
        const val KEY_TRANSPORT_PREFIX = "transport_"
        const val KEY_DIRECT_CONTACT_LINKS = "direct_contact_links"
        const val AUTO_LOCK_AFTER_MS = 60_000L
        const val RECONNECT_INTERVAL_MS = 30_000L
        /** Longer than the joining side waits for its user to confirm. */
        const val HOTSPOT_WAIT_MS = 150_000L
        /** A contact this device asked for a hotspot is not asked back for one within this time. */
        const val ASK_BACK_AFTER_MS = 300_000L
        /** A hotspot joined for messages is left after this long without one. */
        const val MESSAGES_QUIET_MS = 180_000L
        const val TICK_INTERVAL_MS = 5_000L
        const val BUSY_RECHECK_MS = 5_000L
        const val REFRESH_MIN_INTERVAL_MS = 60_000L
        const val REPLACE_RETRY_MS = 60_000L
        const val REPLACE_RETRY_MAX_MS = 10 * 60_000L
    }
}
