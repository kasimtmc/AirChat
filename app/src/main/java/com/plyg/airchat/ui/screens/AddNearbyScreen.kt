package com.plyg.airchat.ui.screens

import androidx.activity.compose.BackHandler
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.Surface
import androidx.compose.ui.draw.clip
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.plyg.airchat.R
import com.plyg.airchat.ui.label
import com.plyg.airchat.ui.NearbyDevice
import com.plyg.airchat.ui.PairingUi
import com.plyg.airchat.ui.QrCode
import com.plyg.airchat.ui.QrScanner

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AddNearbyScreen(
    pairing: PairingUi,
    onPick: (NearbyDevice) -> Unit,
    onConfirmSas: () -> Unit,
    onRejectSas: () -> Unit,
    onDismissResult: () -> Unit,
    onClose: () -> Unit,
    onShowCode: () -> Unit,
    onHideCode: () -> Unit,
    /** Opens the scanner once the camera may be used. */
    onScan: (open: () -> Unit) -> Unit,
    onScanned: (text: String) -> Unit,
) {
    BackHandler(onBack = onClose)
    var scanning by remember { mutableStateOf(false) }
    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.add_nearby)) },
                navigationIcon = {
                    IconButton(onClick = onClose) {
                        Icon(painterResource(R.drawable.ic_back), contentDescription = stringResource(R.string.back))
                    }
                },
            )
        },
    ) { padding ->
        Column(
            modifier = Modifier.fillMaxSize().padding(padding),
            verticalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            Surface(
                color = MaterialTheme.colorScheme.primaryContainer,
                shape = RoundedCornerShape(24.dp),
                modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp),
            ) {
                Column(
                    Modifier.fillMaxWidth().padding(20.dp),
                    horizontalAlignment = Alignment.CenterHorizontally,
                    verticalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    Text(stringResource(R.string.this_device_is), style = MaterialTheme.typography.labelLarge)
                    Text(pairing.ownLabel.orEmpty(), fontSize = 40.sp)
                    Text(
                        stringResource(R.string.this_device_hint),
                        style = MaterialTheme.typography.bodyMedium,
                        textAlign = TextAlign.Center,
                    )
                }
            }
            // QR invites (rust/airchat-protocol/docs/protocol.md §4.4): no emoji to compare.
            Row(Modifier.padding(horizontal = 16.dp), horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                FilledTonalButton(onClick = onShowCode, modifier = Modifier.weight(1f).height(48.dp)) {
                    Icon(painterResource(R.drawable.ic_qr), contentDescription = null, modifier = Modifier.size(18.dp))
                    Spacer(Modifier.width(8.dp))
                    Text(stringResource(R.string.show_my_code))
                }
                FilledTonalButton(onClick = { onScan { scanning = true } }, modifier = Modifier.weight(1f).height(48.dp)) {
                    Text(stringResource(R.string.scan_code))
                }
            }
            Row(
                Modifier.padding(horizontal = 16.dp),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(12.dp),
            ) {
                Text(
                    stringResource(R.string.nearby_devices),
                    style = MaterialTheme.typography.titleSmall,
                    color = MaterialTheme.colorScheme.primary,
                )
                if (pairing.devices.isEmpty() || pairing.connecting) {
                    CircularProgressIndicator(Modifier.size(16.dp), strokeWidth = 2.dp)
                }
            }
            if (pairing.devices.isEmpty()) {
                Text(
                    stringResource(R.string.searching_nearby),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.padding(horizontal = 16.dp),
                )
            }
            LazyColumn {
                items(pairing.devices, key = { it.key }) { device ->
                    NearbyRow(device, enabled = !pairing.connecting) { onPick(device) }
                }
            }
        }
    }

    pairing.invite?.let { code ->
        AlertDialog(
            onDismissRequest = onHideCode,
            title = { Text(stringResource(R.string.show_my_code)) },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                    QrCode(code, Modifier.fillMaxWidth())
                    Text(stringResource(R.string.my_code_explainer), style = MaterialTheme.typography.bodySmall)
                }
            },
            confirmButton = { TextButton(onClick = onHideCode) { Text(stringResource(R.string.close)) } },
        )
    }

    if (scanning) {
        AlertDialog(
            onDismissRequest = { scanning = false },
            title = { Text(stringResource(R.string.scan_contact_title)) },
            text = {
                QrScanner(
                    onRead = { text ->
                        scanning = false
                        onScanned(text)
                    },
                    modifier = Modifier.fillMaxWidth().height(320.dp),
                )
            },
            confirmButton = {},
            dismissButton = { TextButton(onClick = { scanning = false }) { Text(stringResource(R.string.cancel)) } },
        )
    }

    pairing.sas?.let { sas ->
        AlertDialog(
            onDismissRequest = {},
            title = { Text(stringResource(R.string.compare_emoji_title)) },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(16.dp)) {
                    Text(
                        sas.emoji.joinToString(" "),
                        fontSize = 36.sp,
                        textAlign = TextAlign.Center,
                        modifier = Modifier
                            .fillMaxWidth()
                            .semantics { contentDescription = sas.emoji.joinToString(", ") },
                    )
                    Text(
                        stringResource(if (sas.confirmed) R.string.waiting_for_other_device else R.string.compare_emoji_body),
                        style = MaterialTheme.typography.bodyMedium,
                    )
                }
            },
            confirmButton = {
                TextButton(onClick = onConfirmSas, enabled = !sas.confirmed) { Text(stringResource(R.string.emoji_match)) }
            },
            dismissButton = {
                TextButton(onClick = onRejectSas) {
                    Text(stringResource(R.string.emoji_differ), color = MaterialTheme.colorScheme.error)
                }
            },
        )
    }

    val result = pairing.pairedWith?.let { stringResource(R.string.paired_with, it) }
        ?: pairing.failure?.let { stringResource(it) }
    result?.let { message ->
        AlertDialog(
            onDismissRequest = onDismissResult,
            text = { Text(message) },
            confirmButton = {
                TextButton(onClick = if (pairing.pairedWith != null) onClose else onDismissResult) {
                    Text(stringResource(R.string.ok))
                }
            },
        )
    }
}

/** A device nearby, as its own screen shows it: its emoji in a circle, its number, what reaches it. */
@Composable
private fun NearbyRow(device: NearbyDevice, enabled: Boolean, onClick: () -> Unit) {
    Row(
        Modifier.fillMaxWidth().clickable(enabled = enabled, onClick = onClick).padding(horizontal = 16.dp, vertical = 10.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        Box(
            Modifier.size(52.dp).clip(CircleShape).background(MaterialTheme.colorScheme.surfaceContainerHigh),
            contentAlignment = Alignment.Center,
        ) {
            Text(device.label.substringBefore(' '), fontSize = 26.sp)
        }
        Column(Modifier.weight(1f)) {
            Text(device.label, style = MaterialTheme.typography.titleMedium)
            Text(
                device.via.map { stringResource(it.label) }.joinToString(" · "),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}
