package com.plyg.airchat.ui.screens

import androidx.activity.compose.BackHandler
import androidx.compose.foundation.clickable
import androidx.compose.foundation.gestures.detectTapGestures
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.text.input.TextFieldLineLimits
import androidx.compose.foundation.text.input.TextObfuscationMode
import androidx.compose.foundation.text.input.rememberTextFieldState
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.ListItem
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedSecureTextField
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import com.plyg.airchat.R
import com.plyg.airchat.core.EndReason
import com.plyg.airchat.core.WalkieChannel
import com.plyg.airchat.runtime.TalkRefusal
import com.plyg.airchat.runtime.TalkUi
import com.plyg.airchat.ui.QrCode
import com.plyg.airchat.ui.QrScanner
import com.plyg.airchat.ui.WalkieUi

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun WalkieScreen(
    walkie: WalkieUi,
    talk: TalkUi?,
    talkRefused: TalkRefusal?,
    error: Int?,
    /** Back, as this is a tab of the main screen: to the chats. */
    onBack: () -> Unit,
    onCreate: (name: String) -> Unit,
    /** Opens the scanner once the camera may be used. */
    onScan: (open: () -> Unit) -> Unit,
    onScanned: (text: String) -> Unit,
    onPassword: (name: String, password: CharSequence) -> Unit,
    onTune: (channelId: Long?) -> Unit,
    onShare: (WalkieChannel) -> Unit,
    onDismissShare: () -> Unit,
    onDelete: (WalkieChannel) -> Unit,
    onTalkStart: () -> Boolean,
    onTalkEnd: () -> Unit,
    /** Mutes a channel until a time (Unix ms), or unmutes it with 0. */
    onMute: (WalkieChannel, Long) -> Unit,
) {
    BackHandler(onBack = onBack)
    var creating by remember { mutableStateOf(false) }
    var withPassword by remember { mutableStateOf(false) }
    var scanning by remember { mutableStateOf(false) }
    var muting by remember { mutableStateOf<WalkieChannel?>(null) }
    val tuned = walkie.tuned

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.walkie)) },
            )
        },
    ) { padding ->
        LazyColumn(
            modifier = Modifier.fillMaxSize().padding(padding),
            contentPadding = PaddingValues(start = 16.dp, end = 16.dp, top = 8.dp, bottom = 32.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            if (tuned != null) {
                item {
                    TunedCard(
                        channel = tuned,
                        walkie = walkie,
                        talk = talk?.takeIf { it.channelId == tuned.id },
                        refusal = talkRefused?.takeIf { it.channelId == tuned.id },
                        onTalkStart = onTalkStart,
                        onTalkEnd = onTalkEnd,
                        onShare = { onShare(tuned) },
                        onTuneOut = { onTune(null) },
                        onMute = { if (isMuted(tuned.mutedUntil)) onMute(tuned, 0) else muting = tuned },
                    )
                }
            }
            item { ErrorText(error) }
            item {
                Text(stringResource(R.string.walkie_channels), style = MaterialTheme.typography.titleMedium)
            }
            if (walkie.channels.isEmpty()) {
                item {
                    Text(
                        stringResource(R.string.walkie_no_channels),
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }
            items(walkie.channels, key = { it.id }) { channel ->
                ChannelRow(
                    channel,
                    onTune = { onTune(channel.id) },
                    onShare = { onShare(channel) },
                    onDelete = { onDelete(channel) },
                    onMute = { muting = channel },
                    onUnmute = { onMute(channel, 0) },
                )
                HorizontalDivider()
            }
            if (walkie.deriving) {
                item {
                    Column {
                        Text(stringResource(R.string.walkie_joining), style = MaterialTheme.typography.bodySmall)
                        LinearProgressIndicator(Modifier.fillMaxWidth().padding(top = 4.dp))
                    }
                }
            }
            item {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    OutlinedButton(onClick = { creating = true }, modifier = Modifier.fillMaxWidth()) {
                        Text(stringResource(R.string.walkie_new))
                    }
                    OutlinedButton(onClick = { onScan { scanning = true } }, modifier = Modifier.fillMaxWidth()) {
                        Text(stringResource(R.string.walkie_join_qr))
                    }
                    OutlinedButton(onClick = { withPassword = true }, modifier = Modifier.fillMaxWidth()) {
                        Text(stringResource(R.string.walkie_join_password))
                    }
                }
            }
        }
    }

    if (creating) {
        NameDialog(
            title = stringResource(R.string.walkie_new),
            onDismiss = { creating = false },
            onDone = { name ->
                creating = false
                onCreate(name)
            },
        )
    }
    if (withPassword) {
        PasswordDialog(
            onDismiss = { withPassword = false },
            onDone = { name, password ->
                withPassword = false
                onPassword(name, password)
            },
        )
    }
    if (scanning) {
        AlertDialog(
            onDismissRequest = { scanning = false },
            title = { Text(stringResource(R.string.walkie_scan_title)) },
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
    muting?.let { channel ->
        MuteDialog(R.string.mute_channel_explainer, onDismiss = { muting = null }) {
            muting = null
            onMute(channel, it)
        }
    }
    walkie.sharing?.let { (code, name) ->
        AlertDialog(
            onDismissRequest = onDismissShare,
            title = { Text(name) },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                    QrCode(code, Modifier.fillMaxWidth())
                    Text(stringResource(R.string.walkie_share_explainer), style = MaterialTheme.typography.bodySmall)
                }
            },
            confirmButton = { TextButton(onClick = onDismissShare) { Text(stringResource(R.string.close)) } },
        )
    }
}

/** The channel tuned in: who is around, and the button to talk. */
@Composable
private fun TunedCard(
    channel: WalkieChannel,
    walkie: WalkieUi,
    talk: TalkUi?,
    refusal: TalkRefusal?,
    onTalkStart: () -> Boolean,
    onTalkEnd: () -> Unit,
    onShare: () -> Unit,
    onTuneOut: () -> Unit,
    onMute: () -> Unit,
) {
    val someone = stringResource(R.string.walkie_someone)
    val names = walkie.peers.map { it.name.ifBlank { someone } }
    Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.primaryContainer)) {
        Column(
            Modifier.fillMaxWidth().padding(20.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Text(channel.name, style = MaterialTheme.typography.headlineSmall, textAlign = TextAlign.Center)
            mutedText(channel.mutedUntil)?.let {
                Text("🔕 $it", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
            }
            Text(
                if (names.isEmpty()) {
                    stringResource(R.string.walkie_nobody)
                } else {
                    stringResource(R.string.walkie_nearby, names.size, names.joinToString(", "))
                },
                style = MaterialTheme.typography.bodyMedium,
                textAlign = TextAlign.Center,
            )
            val talker = talk?.takeIf { !it.talking }?.let { t ->
                walkie.peers.find { it.id == t.contactId }?.name?.ifBlank { someone } ?: someone
            }
            Text(
                when {
                    talk?.talking == true -> stringResource(R.string.talking)
                    talker != null -> stringResource(R.string.contact_talking, talker)
                    refusal != null && refusal.reason == EndReason.INTERRUPTED -> stringResource(R.string.walkie_interrupted)
                    else -> stringResource(R.string.walkie_hold)
                },
                style = MaterialTheme.typography.titleMedium,
                color = if (talk != null) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurfaceVariant,
            )
            BigTalkButton(talking = talk?.talking == true, hearing = talker != null, onTalkStart, onTalkEnd)
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                TextButton(onClick = onShare) { Text(stringResource(R.string.walkie_share)) }
                TextButton(onClick = onMute) {
                    Text(stringResource(if (isMuted(channel.mutedUntil)) R.string.unmute else R.string.mute))
                }
                TextButton(onClick = onTuneOut) { Text(stringResource(R.string.walkie_tune_out)) }
            }
        }
    }
}

/** Push-to-talk for the channel: talks while held. */
@Composable
private fun BigTalkButton(talking: Boolean, hearing: Boolean, onStart: () -> Boolean, onEnd: () -> Unit) {
    val label = stringResource(R.string.push_to_talk)
    Surface(
        shape = CircleShape,
        color = when {
            talking -> MaterialTheme.colorScheme.error
            hearing -> MaterialTheme.colorScheme.tertiary
            else -> MaterialTheme.colorScheme.primary
        },
        contentColor = MaterialTheme.colorScheme.onPrimary,
        modifier = Modifier
            .size(160.dp)
            .semantics { contentDescription = label }
            .pointerInput(Unit) {
                detectTapGestures(onPress = {
                    if (onStart()) {
                        tryAwaitRelease()
                        onEnd()
                    }
                })
            },
    ) {
        Box(contentAlignment = Alignment.Center) {
            Icon(painterResource(R.drawable.ic_mic), contentDescription = null, modifier = Modifier.size(64.dp))
        }
    }
}

@Composable
private fun ChannelRow(
    channel: WalkieChannel,
    onTune: () -> Unit,
    onShare: () -> Unit,
    onDelete: () -> Unit,
    onMute: () -> Unit,
    onUnmute: () -> Unit,
) {
    var menu by remember { mutableStateOf(false) }
    var confirmDelete by remember { mutableStateOf(false) }
    ListItem(
        leadingContent = { RadioButton(selected = channel.tuned, onClick = onTune) },
        headlineContent = { Text(mutedName(channel.name, channel.mutedUntil)) },
        trailingContent = {
            Box {
                IconButton(onClick = { menu = true }) { Text("⋮", style = MaterialTheme.typography.titleLarge) }
                DropdownMenu(expanded = menu, onDismissRequest = { menu = false }) {
                    DropdownMenuItem(
                        text = { Text(stringResource(R.string.walkie_share)) },
                        onClick = {
                            menu = false
                            onShare()
                        },
                    )
                    MuteMenuItem(
                        channel.mutedUntil,
                        onMute = {
                            menu = false
                            onMute()
                        },
                        onUnmute = {
                            menu = false
                            onUnmute()
                        },
                    )
                    DropdownMenuItem(
                        text = { Text(stringResource(R.string.walkie_delete), color = MaterialTheme.colorScheme.error) },
                        onClick = {
                            menu = false
                            confirmDelete = true
                        },
                    )
                }
            }
        },
        modifier = Modifier.clickable(onClick = onTune),
    )
    if (confirmDelete) {
        AlertDialog(
            onDismissRequest = { confirmDelete = false },
            title = { Text(stringResource(R.string.walkie_delete)) },
            text = { Text(channel.name) },
            confirmButton = {
                TextButton(onClick = {
                    confirmDelete = false
                    onDelete()
                }) { Text(stringResource(R.string.delete), color = MaterialTheme.colorScheme.error) }
            },
            dismissButton = { TextButton(onClick = { confirmDelete = false }) { Text(stringResource(R.string.cancel)) } },
        )
    }
}

@Composable
private fun NameDialog(title: String, onDismiss: () -> Unit, onDone: (String) -> Unit) {
    val name = rememberTextFieldState()
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(title) },
        text = {
            OutlinedTextField(
                state = name,
                label = { Text(stringResource(R.string.walkie_channel_name)) },
                lineLimits = TextFieldLineLimits.SingleLine,
                modifier = Modifier.fillMaxWidth(),
            )
        },
        confirmButton = {
            TextButton(enabled = name.text.isNotBlank(), onClick = { onDone(name.text.toString()) }) {
                Text(stringResource(R.string.create))
            }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text(stringResource(R.string.cancel)) } },
    )
}

@Composable
private fun PasswordDialog(onDismiss: () -> Unit, onDone: (name: String, password: CharSequence) -> Unit) {
    val name = rememberTextFieldState()
    val password = rememberTextFieldState()
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(stringResource(R.string.walkie_join_password)) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                OutlinedTextField(
                    state = name,
                    label = { Text(stringResource(R.string.walkie_channel_name)) },
                    lineLimits = TextFieldLineLimits.SingleLine,
                    modifier = Modifier.fillMaxWidth(),
                )
                OutlinedSecureTextField(
                    state = password,
                    label = { Text(stringResource(R.string.walkie_password)) },
                    textObfuscationMode = TextObfuscationMode.RevealLastTyped,
                    modifier = Modifier.fillMaxWidth(),
                )
                Text(stringResource(R.string.walkie_password_explainer), style = MaterialTheme.typography.bodySmall)
            }
        },
        confirmButton = {
            TextButton(
                enabled = name.text.isNotBlank() && password.text.length >= 8,
                onClick = {
                    onDone(name.text.toString(), password.text)
                    password.edit { replace(0, length, "") }
                },
            ) { Text(stringResource(R.string.create)) }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text(stringResource(R.string.cancel)) } },
    )
}
