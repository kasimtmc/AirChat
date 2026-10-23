package com.plyg.airchat.net

import android.annotation.SuppressLint
import android.bluetooth.BluetoothDevice
import android.bluetooth.BluetoothGatt
import android.bluetooth.BluetoothGattCallback
import android.bluetooth.BluetoothProfile
import android.bluetooth.BluetoothSocket
import android.content.Context
import android.util.Log
import com.plyg.airchat.shared.BuildConfig
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import java.io.FilterInputStream
import java.io.FilterOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.util.concurrent.atomic.AtomicLong

/**
 * An LE L2CAP channel, with its radio link tuned for throughput while it carries bulk data.
 *
 * Android offers no tuning for L2CAP channels themselves, only through a GATT client on the same
 * link. So a GATT client is attached that never discovers services or reads anything; it only
 * negotiates: an ATT MTU exchange, after which the stack also turns on long link-layer packets
 * (data length extension, 251 instead of 27 bytes) for the link; the 2M PHY; and, only while data
 * flows in bulk, a short connection interval. None of these carries an identifier.
 */
@SuppressLint("MissingPermission") // Only created while the BLE transport runs, which needs it.
class BleLink(context: Context, private val socket: BluetoothSocket, scope: CoroutineScope) : StreamChannel {
    private val traffic = AtomicLong()
    @Volatile private var gatt: BluetoothGatt? = null
    @Volatile private var fast = false
    @Volatile private var closed = false

    init {
        gatt = socket.remoteDevice.connectGatt(
            context,
            false,
            object : BluetoothGattCallback() {
                override fun onConnectionStateChange(gatt: BluetoothGatt, status: Int, newState: Int) {
                    if (newState != BluetoothProfile.STATE_CONNECTED || closed) return
                    gatt.setPreferredPhy(BluetoothDevice.PHY_LE_2M_MASK, BluetoothDevice.PHY_LE_2M_MASK, BluetoothDevice.PHY_OPTION_NO_PREFERRED)
                    gatt.requestMtu(MTU)
                    if (fast) gatt.requestConnectionPriority(BluetoothGatt.CONNECTION_PRIORITY_HIGH)
                }

                override fun onMtuChanged(gatt: BluetoothGatt, mtu: Int, status: Int) {
                    debug { "BLE link MTU $mtu (status $status)" }
                }

                override fun onPhyUpdate(gatt: BluetoothGatt, txPhy: Int, rxPhy: Int, status: Int) {
                    debug { "BLE link PHY tx $txPhy rx $rxPhy (status $status)" }
                }
            },
            BluetoothDevice.TRANSPORT_LE,
        )
        scope.launch {
            var quiet = 0
            while (!closed) {
                delay(CHECK_MS)
                val busy = traffic.getAndSet(0) >= BUSY_BYTES
                quiet = if (busy) 0 else quiet + 1
                when {
                    busy && !fast -> setFast(true)
                    fast && quiet >= QUIET_CHECKS -> setFast(false)
                }
            }
        }
    }

    private fun setFast(value: Boolean) {
        fast = value
        val priority = if (value) BluetoothGatt.CONNECTION_PRIORITY_HIGH else BluetoothGatt.CONNECTION_PRIORITY_BALANCED
        val asked = gatt?.requestConnectionPriority(priority) == true
        debug { "BLE link ${if (value) "busy: short" else "quiet: normal"} connection interval (asked: $asked)" }
    }

    override val input: InputStream = object : FilterInputStream(socket.inputStream) {
        override fun read(): Int = super.read().also { if (it >= 0) traffic.incrementAndGet() }

        override fun read(b: ByteArray, off: Int, len: Int): Int =
            super.read(b, off, len).also { if (it > 0) traffic.addAndGet(it.toLong()) }
    }

    override val output: OutputStream = object : FilterOutputStream(socket.outputStream) {
        override fun write(b: ByteArray, off: Int, len: Int) {
            out.write(b, off, len)
            traffic.addAndGet(len.toLong())
        }
    }

    override fun close() {
        closed = true
        gatt?.let {
            it.disconnect()
            it.close()
        }
        gatt = null
        socket.close()
    }

    private inline fun debug(message: () -> String) {
        if (BuildConfig.DEBUG) Log.d(TAG, message())
    }

    private companion object {
        const val TAG = "AirChat"
        const val MTU = 517
        const val CHECK_MS = 2_000L
        /** Bytes in one check that count as bulk: a few file chunks. */
        const val BUSY_BYTES = 32 * 1024L
        /** Quiet checks before the link goes back to the normal, battery-friendly interval. */
        const val QUIET_CHECKS = 5
    }
}
