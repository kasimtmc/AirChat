package com.plyg.airchat.net

import android.annotation.SuppressLint
import android.bluetooth.BluetoothAdapter
import android.bluetooth.BluetoothDevice
import android.bluetooth.BluetoothManager
import android.bluetooth.BluetoothServerSocket
import android.bluetooth.BluetoothSocket
import android.bluetooth.le.AdvertiseData
import android.bluetooth.le.AdvertisingSet
import android.bluetooth.le.AdvertisingSetCallback
import android.bluetooth.le.AdvertisingSetParameters
import android.bluetooth.le.ScanCallback
import android.bluetooth.le.ScanFilter
import android.bluetooth.le.ScanResult
import android.bluetooth.le.ScanSettings
import android.content.Context
import android.os.ParcelUuid
import android.os.SystemClock
import android.util.Log
import com.plyg.airchat.shared.BuildConfig
import com.plyg.airchat.core.BleBeacon
import com.plyg.airchat.core.bleServiceUuid
import com.plyg.airchat.core.decodeBleBeacon
import com.plyg.airchat.core.encodeBleBeacon
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.launch
import java.io.IOException

/** Another AirChat device in Bluetooth range: one of its advertisements. */
class BlePeer(
    private val device: BluetoothDevice,
    val psm: Int,
    override val pairingToken: ByteArray?,
    override val presenceToken: ByteArray?,
    override val channelToken: ByteArray?,
    private val open: (BluetoothSocket) -> StreamChannel,
    override val requestToken: ByteArray? = null,
) : Peer {
    override val kind get() = TransportKind.BLE

    @SuppressLint("MissingPermission") // Peers exist only while the transport runs, which needs it.
    override fun connect(): StreamChannel {
        val socket = device.createInsecureL2capChannel(psm)
        try {
            socket.connect()
        } catch (e: IOException) {
            runCatching { socket.close() }
            throw e
        }
        return open(socket)
    }

    fun sameAs(other: BlePeer) = psm == other.psm &&
        pairingToken contentEquals other.pairingToken &&
        presenceToken contentEquals other.presenceToken &&
        channelToken contentEquals other.channelToken &&
        requestToken contentEquals other.requestToken

    /** Announces the same token, so it is the same device, perhaps under a new address or PSM. */
    fun sameDeviceAs(other: BlePeer) =
        presenceToken?.contentEquals(other.presenceToken) == true ||
            pairingToken?.contentEquals(other.pairingToken) == true ||
            channelToken?.contentEquals(other.channelToken) == true ||
            requestToken?.contentEquals(other.requestToken) == true

    /** Which of the device's beacons this is: it advertises each from its own set. */
    val beaconKind get() = when {
        pairingToken != null -> "pairing"
        channelToken != null -> "channel"
        requestToken != null -> "request"
        else -> "presence"
    }
}

/**
 * Bluetooth Low Energy transport (rust/airchat-protocol/docs/protocol.md §7.3): beacons in advertisements, connections
 * over an LE L2CAP channel without Bluetooth pairing; the AirChat session protects everything.
 *
 * Presence, pairing, channel and request beacons go out as separate advertising sets, so they share no address. When
 * the presence token changes (hourly), the channel is opened again under a new PSM and the sets get
 * the new data in place.
 *
 * Scans and advertising sets are started as rarely as possible, and their data is changed in place
 * of restarts: on some phones (seen on MIUI) ones started while the app is in the background quietly
 * never run. Failed starts are retried, and [refresh] starts everything afresh when the app comes to
 * the front.
 */
@SuppressLint("MissingPermission") // The runtime starts this transport only with the permissions granted.
class BleTransport(
    private val context: Context,
    private val hub: ConnectionHub,
    private val scope: CoroutineScope,
    private val presenceToken: () -> ByteArray,
    private val channelToken: () -> ByteArray?,
    private val requestToken: () -> ByteArray?,
) : Transport {
    override val kind get() = TransportKind.BLE

    private val adapter: BluetoothAdapter? = context.getSystemService(BluetoothManager::class.java)?.adapter
    private val serviceUuid = ParcelUuid.fromString(bleServiceUuid())

    private var stopped = false
    private var server: BluetoothServerSocket? = null
    private var psm = 0
    private var announcedPresence: ByteArray? = null
    private var pairingToken: ByteArray? = null
    private val presence = Advertisement(fast = false)
    /** Fast, so the device shows up in "Add nearby" lists at once. */
    private val pairing = Advertisement(fast = true)
    private var announcedChannel: ByteArray? = null
    private val channel = Advertisement(fast = false)
    private var announcedRequest: ByteArray? = null
    private val request = Advertisement(fast = false)
    private var scanning: ScanCallback? = null
    private var scanFailures = 0
    private var scanRetry: Job? = null
    private val jobs = mutableListOf<Job>()

    private class Sighting(val peer: BlePeer, var at: Long)

    /** The latest sighting of each announcement, by device address and beacon kind. */
    private val seen = mutableMapOf<String, Sighting>()

    private val _peers = MutableStateFlow<List<Peer>>(emptyList())
    override val peers: StateFlow<List<Peer>> = _peers

    override fun start() {
        val adapter = adapter?.takeIf { it.isEnabled } ?: throw IOException("Bluetooth is off")
        if (adapter.bluetoothLeAdvertiser == null || adapter.bluetoothLeScanner == null) {
            throw IOException("BLE advertising or scanning unavailable")
        }
        listen()
        advertisePresence()
        channelChanged()
        requestChanged()
        scan()
        jobs += scope.launch {
            while (true) {
                delay(ROTATION_CHECK_MS)
                if (!presenceToken().contentEquals(announcedPresence)) rotate()
                channelChanged()
                requestChanged()
            }
        }
        jobs += scope.launch {
            while (true) {
                delay(EXPIRY_CHECK_MS)
                expire()
            }
        }
    }

    override fun stop() {
        stopped = true
        jobs.forEach { it.cancel() }
        jobs.clear()
        scanRetry?.cancel()
        scanning?.let { callback -> runCatching { adapter?.bluetoothLeScanner?.stopScan(callback) } }
        scanning = null
        presence.stop()
        pairing.stop()
        channel.stop()
        request.stop()
        announcedChannel = null
        announcedRequest = null
        pairingToken = null
        closeServer()
        seen.clear()
        publish()
    }

    override fun refresh() {
        if (stopped) return
        debug { "refreshing BLE scan and advertising" }
        scan()
        presence.restart()
        pairing.restart()
        channel.restart()
        request.restart()
    }

    override fun channelChanged() {
        if (stopped) return
        val token = channelToken()
        if (token contentEquals announcedChannel) return
        announcedChannel = token
        if (token == null) channel.stop() else channel.show(BleBeacon.Channel(psm.toUShort(), token))
    }

    override fun requestChanged() {
        if (stopped) return
        val token = requestToken()
        if (token contentEquals announcedRequest) return
        announcedRequest = token
        if (token == null) request.stop() else request.show(BleBeacon.Request(psm.toUShort(), token))
    }

    override fun setPairingToken(token: ByteArray?) {
        val modeChanged = (token != null) != (pairingToken != null)
        pairingToken = token
        if (token == null) pairing.stop() else pairing.show(BleBeacon.Pairing(psm.toUShort(), token))
        // Look harder while the user waits for a device to appear in "Add nearby".
        if (modeChanged && scanning != null) scan()
    }

    private fun listen() {
        val socket = checkNotNull(adapter).listenUsingInsecureL2capChannel()
        server = socket
        psm = socket.psm
        scope.launch(Dispatchers.IO) {
            try {
                while (true) hub.attach(link(socket.accept()), TransportKind.BLE)
            } catch (_: IOException) {
                // Closed by stop() or rotate(), or Bluetooth went off.
            }
        }
    }

    private fun link(socket: BluetoothSocket): StreamChannel = BleLink(context, socket, scope)

    private fun closeServer() {
        runCatching { server?.close() }
        server = null
    }

    /** New presence token: a new channel (new PSM), announced in place. */
    private fun rotate() {
        closeServer()
        try {
            listen()
        } catch (e: IOException) {
            if (BuildConfig.DEBUG) Log.w(TAG, "could not reopen the L2CAP channel", e)
            return
        }
        advertisePresence()
        pairingToken?.let { pairing.show(BleBeacon.Pairing(psm.toUShort(), it)) }
        announcedChannel?.let { channel.show(BleBeacon.Channel(psm.toUShort(), it)) }
        announcedRequest?.let { request.show(BleBeacon.Request(psm.toUShort(), it)) }
    }

    private fun advertisePresence() {
        val token = presenceToken()
        announcedPresence = token
        presence.show(BleBeacon.Presence(psm.toUShort(), token))
    }

    /** Exactly 31 bytes with a presence beacon: flags (3) + service data (2 + 16 + 10). */
    private fun content(data: ByteArray) = AdvertiseData.Builder()
        .setIncludeDeviceName(false)
        .setIncludeTxPowerLevel(false)
        .addServiceData(serviceUuid, data)
        .build()

    /** One advertising set, whose data can change without stopping it. Main thread. */
    private inner class Advertisement(private val fast: Boolean) {
        private var callback: AdvertisingSetCallback? = null
        private var set: AdvertisingSet? = null
        private var data: ByteArray? = null
        private var failures = 0
        private var retry: Job? = null

        /** Starts announcing `beacon`, or changes what is announced. */
        fun show(beacon: BleBeacon) {
            val data = encodeBleBeacon(beacon) ?: return debug { "PSM $psm cannot be announced" }
            this.data = data
            val set = set
            when {
                set != null -> set.setAdvertisingData(content(data))
                callback == null && retry?.isActive != true -> start()
                else -> Unit // Starting or waiting to retry: the newest data goes out then.
            }
        }

        fun stop() {
            retry?.cancel()
            retry = null
            callback?.let { runCatching { adapter?.bluetoothLeAdvertiser?.stopAdvertisingSet(it) } }
            callback = null
            set = null
            data = null
            failures = 0
        }

        /** Starts again from scratch, in case the platform stopped it without telling. */
        fun restart() {
            val data = data ?: return
            stop()
            this.data = data
            start()
        }

        private fun start() {
            val advertiser = adapter?.bluetoothLeAdvertiser ?: return
            val sent = data ?: return
            val parameters = AdvertisingSetParameters.Builder()
                .setLegacyMode(true)
                .setConnectable(true)
                .setScannable(true)
                .setInterval(if (fast) AdvertisingSetParameters.INTERVAL_LOW else AdvertisingSetParameters.INTERVAL_HIGH)
                .setTxPowerLevel(AdvertisingSetParameters.TX_POWER_HIGH)
                .build()
            val attempt = object : AdvertisingSetCallback() {
                override fun onAdvertisingSetStarted(started: AdvertisingSet?, txPower: Int, status: Int) {
                    if (callback !== this) {
                        // Stopped meanwhile.
                        runCatching { advertiser.stopAdvertisingSet(this) }
                        return
                    }
                    if (status == ADVERTISE_SUCCESS && started != null) {
                        set = started
                        failures = 0
                        data?.takeUnless { it.contentEquals(sent) }?.let { started.setAdvertisingData(content(it)) }
                        debug { "advertising on PSM $psm" }
                    } else {
                        callback = null
                        if (BuildConfig.DEBUG) Log.w(TAG, "advertising failed: $status")
                        retry = scope.launch {
                            delay(backoff(failures++))
                            start()
                        }
                    }
                }
            }
            callback = attempt
            advertiser.startAdvertisingSet(parameters, content(sent), null, null, null, attempt)
        }
    }

    /** (Re)starts the scan, fast while "Add nearby" is open. Filtered, so it also runs with the screen off. */
    private fun scan() {
        val scanner = adapter?.bluetoothLeScanner ?: return
        scanRetry?.cancel()
        scanning?.let { runCatching { scanner.stopScan(it) } }
        // A filtered scan is exempt from Android's 30-minute downgrade to opportunistic scanning.
        val filter = ScanFilter.Builder().setServiceData(serviceUuid, ByteArray(0)).build()
        val settings = ScanSettings.Builder()
            .setScanMode(
                if (pairingToken != null) ScanSettings.SCAN_MODE_LOW_LATENCY else ScanSettings.SCAN_MODE_LOW_POWER,
            )
            .build()
        val callback = object : ScanCallback() {
            override fun onScanResult(callbackType: Int, result: ScanResult) = found(result)

            override fun onBatchScanResults(results: MutableList<ScanResult>) = results.forEach(::found)

            override fun onScanFailed(errorCode: Int) {
                if (scanning !== this) return
                scanning = null
                if (BuildConfig.DEBUG) Log.w(TAG, "scan failed: $errorCode")
                scanRetry = scope.launch {
                    delay(backoff(scanFailures++))
                    scan()
                }
            }
        }
        scanning = callback
        scanner.startScan(listOf(filter), settings, callback)
    }

    private fun found(result: ScanResult) {
        scanFailures = 0
        val data = result.scanRecord?.getServiceData(serviceUuid) ?: return
        val beacon = decodeBleBeacon(data) ?: return debug { "undecodable beacon of ${data.size} bytes" }
        val peer = when (beacon) {
            is BleBeacon.Presence -> BlePeer(result.device, beacon.psm.toInt(), null, beacon.token, null, ::link)
            is BleBeacon.Pairing -> BlePeer(result.device, beacon.psm.toInt(), beacon.token, null, null, ::link)
            is BleBeacon.Channel -> BlePeer(result.device, beacon.psm.toInt(), null, null, beacon.token, ::link)
            is BleBeacon.Request ->
                BlePeer(result.device, beacon.psm.toInt(), null, null, null, ::link, requestToken = beacon.token)
        }
        if (peer.isOwn()) return
        val key = "${result.device.address}/${peer.beaconKind}"
        val now = SystemClock.elapsedRealtime()
        val known = seen[key]
        if (known != null && known.peer.sameAs(peer)) {
            known.at = now
            return
        }
        // Its older announcement under another address or PSM is stale: connecting there would only
        // time out.
        seen.entries.removeAll { (other, sighting) -> other != key && sighting.peer.sameDeviceAs(peer) }
        seen[key] = Sighting(peer, now)
        debug { "heard ${beacon::class.simpleName} on PSM ${peer.psm}" }
        publish()
    }

    /** Our own beacon, should the controller report it. Two absent tokens are no match. */
    private fun BlePeer.isOwn() = presenceToken?.contentEquals(announcedPresence) == true ||
        pairingToken?.contentEquals(this@BleTransport.pairingToken) == true ||
        channelToken?.contentEquals(announcedChannel) == true ||
        requestToken?.contentEquals(announcedRequest) == true

    /** Forgets announcements not heard lately: the device left, or rotated its address or token. */
    private fun expire() {
        val now = SystemClock.elapsedRealtime()
        val removed = seen.values.removeAll { sighting ->
            now - sighting.at > if (sighting.peer.pairingToken != null) PAIRING_TTL_MS else PRESENCE_TTL_MS
        }
        if (removed) publish()
    }

    private fun publish() {
        _peers.value = seen.values.map { it.peer }
    }

    private inline fun debug(message: () -> String) {
        if (BuildConfig.DEBUG) Log.d(TAG, message())
    }

    private companion object {
        const val TAG = "AirChat"
        const val ROTATION_CHECK_MS = 60_000L
        const val EXPIRY_CHECK_MS = 5_000L
        /** Pairing beacons are advertised and scanned fast; presence beacons slowly, to save battery. */
        const val PAIRING_TTL_MS = 10_000L
        const val PRESENCE_TTL_MS = 60_000L

        /** 10 s, doubling up to 5 minutes. */
        fun backoff(failures: Int): Long = minOf(10_000L shl minOf(failures, 5), 300_000L)
    }
}
