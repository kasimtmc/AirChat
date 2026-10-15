package com.plyg.airchat.ui.screens

import android.graphics.BitmapFactory
import android.net.Uri
import android.text.format.Formatter
import androidx.activity.compose.BackHandler
import androidx.annotation.StringRes
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.PickVisualMediaRequest
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.Image
import androidx.compose.foundation.clickable
import androidx.compose.foundation.verticalScroll
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.gestures.detectTapGestures
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.aspectRatio
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.consumeWindowInsets
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.input.clearText
import androidx.compose.foundation.text.input.rememberTextFieldState
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Checkbox
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp
import com.plyg.airchat.R
import com.plyg.airchat.core.Group
import com.plyg.airchat.core.EmergencyExit
import com.plyg.airchat.ui.VoicePlayback
import com.plyg.airchat.core.Attachment
import com.plyg.airchat.core.AttachmentState
import com.plyg.airchat.core.Contact
import com.plyg.airchat.core.ContactState
import com.plyg.airchat.core.EndReason
import com.plyg.airchat.core.Message
import com.plyg.airchat.core.MessageStatus
import com.plyg.airchat.core.Permissions
import com.plyg.airchat.net.TransportKind
import com.plyg.airchat.runtime.TalkRefusal
import com.plyg.airchat.runtime.TalkUi
import com.plyg.airchat.ui.ChatUi
import com.plyg.airchat.ui.label

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ChatScreen(
    chat: ChatUi,
    /** What carries the link to the contact, or null while they are not nearby. */
    via: TransportKind?,
    /** Calls and push-to-talk can be tried: linked, or Air Providers around may find a path. */
    reachable: Boolean = via != null,
    error: Int?,
    notice: Int?,
    onSend: (String) -> Unit,
    onSendFile: (Uri) -> Unit,
    onDownload: (Message) -> Unit,
    onOpen: (Message) -> Unit,
    onBack: () -> Unit,
    onDelete: (keepHistory: Boolean) -> Unit,
    onBlock: () -> Unit,
    onUnblock: () -> Unit,
    onPermissions: (Permissions) -> Unit,
    /** Push-to-talk with this contact, or null. */
    talk: TalkUi?,
    /** The last talk to this contact was cut short. */
    talkRefused: TalkRefusal?,
    onCall: () -> Unit,
    onVideoCall: () -> Unit = {},
    /** Pressed: false if talking cannot start (no link, no microphone yet). */
    onTalkStart: () -> Boolean,
    onTalkEnd: () -> Unit,
    /** Moves the link from Bluetooth to Wi-Fi, which carries messages, calls and files. */
    onMoveToWifi: () -> Unit = {},
    /** Messages to the contact wait for Wi-Fi. */
    waitingForWifi: Boolean = false,
    /** Mutes the contact until a time (Unix ms), or unmutes it with 0. */
    onMute: (Long) -> Unit = {},
    /** This device's own name and its other contacts, to propose a group of three (M-3). */
    ownName: String = "",
    others: List<Contact> = emptyList(),
    onProposeMember: (personId: Long, groupName: String, expiresSecs: Long) -> Unit = { _, _, _ -> },
    /** A message not delivered within a day is tried again (long press). */
    onTryAgain: (Message) -> Unit = {},
    /** The voice message playing, if one is; a tap plays or pauses one. */
    voicePlayback: VoicePlayback? = null,
    onToggleVoice: (Message) -> Unit = {},
    /** The emergency exit (docs/threat-model.md, A5): the groups it touches while confirming,
     * what it did once done. */
    emergencyGroups: List<Group>? = null,
    emergencyResult: EmergencyExit? = null,
    onAskEmergencyExit: () -> Unit = {},
    onEmergencyExit: (leaveGroups: Boolean) -> Unit = {},
    onDismissEmergencyExit: () -> Unit = {},
) {
    BackHandler(onBack = onBack)
    val input = rememberTextFieldState()
    var confirmDelete by remember { mutableStateOf(false) }
    var confirmBlock by remember { mutableStateOf(false) }
    var editPermissions by remember { mutableStateOf(false) }
    var choosingMute by remember { mutableStateOf(false) }
    var contactMenu by remember { mutableStateOf(false) }
    var proposing by remember { mutableStateOf(false) }
    val active = chat.state == ContactState.ACTIVE
    // No storage permission needed: the system pickers grant access to what the user picks.
    val pickMedia = rememberLauncherForActivityResult(ActivityResultContracts.PickVisualMedia()) { uri ->
        uri?.let(onSendFile)
    }
    val pickDocument = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        uri?.let(onSendFile)
    }
    val send = {
        onSend(input.text.toString())
        input.clearText()
    }
    // The newest message is item 0. Follow new ones, unless the user scrolled back to older ones.
    val listState = rememberLazyListState()
    val newest = chat.messages.lastOrNull()
    LaunchedEffect(newest?.id) {
        if (newest?.outgoing == true || listState.firstVisibleItemIndex <= 1) listState.animateScrollToItem(0)
    }

    Scaffold(
        containerColor = chatBackground(),
        topBar = {
            TopAppBar(
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(painterResource(R.drawable.ic_back), contentDescription = stringResource(R.string.back))
                    }
                },
                title = {
                    val talkHere = talk?.takeIf { it.contactId == chat.contactId }
                    ConversationTitle(
                        name = chat.name,
                        title = mutedName(chat.name, chat.mutedUntil),
                        status = when {
                            chat.state == ContactState.BLOCKED -> stringResource(R.string.chat_blocked)
                            chat.state == ContactState.FORMER -> stringResource(R.string.chat_former)
                            talkHere?.voiceMessage == true -> stringResource(R.string.talk_recording_voice)
                            talkHere?.talking == true -> stringResource(R.string.talking)
                            talkHere != null -> stringResource(R.string.contact_talking, chat.name)
                            via == null -> stringResource(R.string.chat_offline)
                            via == TransportKind.RELAY -> stringResource(R.string.chat_relayed)
                            else -> stringResource(R.string.chat_online, stringResource(via.label))
                        },
                        statusActive = via != null || talkHere != null,
                        nearby = active && via != null && via != TransportKind.RELAY,
                        verified = chat.verifiedBuild,
                    )
                },
                actions = {
                    if (active && reachable) {
                        IconButton(onClick = onVideoCall) {
                            Icon(painterResource(R.drawable.ic_videocam), contentDescription = stringResource(R.string.video_call))
                        }
                        IconButton(onClick = onCall) {
                            Icon(painterResource(R.drawable.ic_call), contentDescription = stringResource(R.string.call))
                        }
                    }
                    Box {
                        val options = stringResource(R.string.contact_options)
                        IconButton(onClick = { contactMenu = true }) {
                            Icon(painterResource(R.drawable.ic_more_vert), contentDescription = options)
                        }
                        DropdownMenu(expanded = contactMenu, onDismissRequest = { contactMenu = false }) {
                            if (active) {
                                // One tap to accept push-to-talk or not; the rest in the chat settings.
                                DropdownMenuItem(
                                    text = { Text(stringResource(R.string.permission_ptt)) },
                                    trailingIcon = { Checkbox(checked = chat.permissions.ptt, onCheckedChange = null) },
                                    onClick = {
                                        contactMenu = false
                                        onPermissions(chat.permissions.copy(ptt = !chat.permissions.ptt))
                                    },
                                )
                                DropdownMenuItem(
                                    text = { Text(stringResource(R.string.contact_permissions)) },
                                    onClick = {
                                        contactMenu = false
                                        editPermissions = true
                                    },
                                )
                                DropdownMenuItem(
                                    text = { Text(stringResource(R.string.propose_member)) },
                                    onClick = {
                                        contactMenu = false
                                        proposing = true
                                    },
                                )
                                MuteMenuItem(
                                    chat.mutedUntil,
                                    onMute = {
                                        contactMenu = false
                                        choosingMute = true
                                    },
                                    onUnmute = {
                                        contactMenu = false
                                        onMute(0)
                                    },
                                )
                            }
                            when (chat.state) {
                                ContactState.ACTIVE -> DropdownMenuItem(
                                    text = { Text(stringResource(R.string.block)) },
                                    onClick = {
                                        contactMenu = false
                                        confirmBlock = true
                                    },
                                )
                                ContactState.BLOCKED -> DropdownMenuItem(
                                    text = { Text(stringResource(R.string.unblock)) },
                                    onClick = {
                                        contactMenu = false
                                        onUnblock()
                                    },
                                )
                                // Peers have no conversation of their own.
                                ContactState.FORMER, ContactState.PEER -> Unit
                            }
                            if (chat.state == ContactState.ACTIVE || chat.state == ContactState.BLOCKED) {
                                DropdownMenuItem(
                                    text = { Text(stringResource(R.string.emergency_exit), color = MaterialTheme.colorScheme.error) },
                                    onClick = {
                                        contactMenu = false
                                        onAskEmergencyExit()
                                    },
                                )
                            }
                            DropdownMenuItem(
                                text = { Text(stringResource(R.string.delete), color = MaterialTheme.colorScheme.error) },
                                onClick = {
                                    contactMenu = false
                                    confirmDelete = true
                                },
                            )
                        }
                    }
                },
            )
        },
    ) { padding ->
        // The Scaffold's padding already holds the navigation bar; the keyboard adds what goes past it.
        Column(Modifier.fillMaxSize().padding(padding).consumeWindowInsets(padding).imePadding()) {
            // Bluetooth finds the contact; messages, calls and files need Wi-Fi (protocol §7.3).
            if (active && via == TransportKind.BLE) {
                Surface(
                    color = MaterialTheme.colorScheme.secondaryContainer,
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Row(
                        Modifier.padding(start = 16.dp, end = 8.dp, top = 4.dp, bottom = 4.dp),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Text(
                            stringResource(if (waitingForWifi) R.string.wifi_waiting_banner else R.string.wifi_needed_banner),
                            style = MaterialTheme.typography.bodySmall,
                            modifier = Modifier.weight(1f),
                        )
                        TextButton(onClick = onMoveToWifi) { Text(stringResource(R.string.move_to_wifi)) }
                    }
                }
            }
            MessageList(
                chat.messages,
                key = { it.id },
                at = { it.storedAtMs },
                from = { it.outgoing },
                listState = listState,
                empty = stringResource(R.string.no_messages),
                modifier = Modifier.weight(1f).fillMaxWidth(),
            ) { message, _, last ->
                MessageBubble(
                    message,
                    tail = last,
                    contactName = chat.name,
                    contactNearby = via != null,
                    onDownload = { onDownload(message) },
                    onOpen = { onOpen(message) },
                    onTryAgain = { onTryAgain(message) },
                    playback = voicePlayback?.takeIf { it.file == message.id },
                    onToggleVoice = { onToggleVoice(message) },
                )
            }
            if (chat.preparing > 0) {
                Column(Modifier.fillMaxWidth().padding(horizontal = 12.dp)) {
                    Text(stringResource(R.string.file_preparing), style = MaterialTheme.typography.bodySmall)
                    LinearProgressIndicator(Modifier.fillMaxWidth().padding(top = 4.dp))
                }
            }
            Box(Modifier.padding(horizontal = 12.dp)) {
                ErrorText(error)
                val refusal = talkRefused?.takeIf { it.contactId == chat.contactId }
                val recording = talk?.takeIf { it.voiceMessage && it.contactId == chat.contactId && it.groupId == null }
                if (error == null && recording != null) {
                    Text(
                        stringResource(R.string.talk_recording_voice_hint, chat.name),
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.primary,
                    )
                } else if (error == null && refusal != null) {
                    Text(
                        stringResource(talkRefusalText(refusal.reason), chat.name),
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.error,
                    )
                } else if (error == null && notice != null) {
                    Text(stringResource(notice), style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.primary)
                }
            }
            if (!active) {
                // Nothing can be sent to a blocked or former contact.
                InactiveContact(chat, onUnblock)
                return@Column
            }
            MessageInput(
                input,
                onSend = send,
                onPickMedia = { pickMedia.launch(PickVisualMediaRequest(ActivityResultContracts.PickVisualMedia.ImageAndVideo)) },
                onPickFile = { pickDocument.launch(arrayOf("*/*")) },
                talk = if (reachable) {
                    { TalkButton(talking = talk?.talking == true && talk.contactId == chat.contactId, onTalkStart, onTalkEnd) }
                } else {
                    null
                },
            )
        }
    }

    if (proposing) {
        ProposeMemberDialog(
            ownName = ownName,
            contactName = chat.name,
            candidates = others.filter { it.state == ContactState.ACTIVE && it.id != chat.contactId },
            onDismiss = { proposing = false },
            onPropose = { person, name, expires ->
                proposing = false
                onProposeMember(person, name, expires)
            },
        )
    }

    if (confirmDelete) {
        // A former contact has only its history left: deleting removes that.
        val former = chat.state == ContactState.FORMER
        var deleteHistory by remember { mutableStateOf(true) }
        AlertDialog(
            onDismissRequest = { confirmDelete = false },
            title = {
                Text(
                    if (former) {
                        stringResource(R.string.delete_history_title, chat.name)
                    } else {
                        stringResource(R.string.delete_conversation_title, chat.name)
                    },
                )
            },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                    Text(stringResource(if (former) R.string.delete_history_body else R.string.delete_conversation_body))
                    if (!former) {
                        Row(
                            verticalAlignment = Alignment.CenterVertically,
                            modifier = Modifier.fillMaxWidth().clickable { deleteHistory = !deleteHistory },
                        ) {
                            Checkbox(checked = deleteHistory, onCheckedChange = { deleteHistory = it })
                            Text(stringResource(R.string.delete_history_too), style = MaterialTheme.typography.bodyMedium)
                        }
                    }
                }
            },
            confirmButton = {
                TextButton(onClick = {
                    confirmDelete = false
                    onDelete(!former && !deleteHistory)
                }) { Text(stringResource(R.string.delete), color = MaterialTheme.colorScheme.error) }
            },
            dismissButton = { TextButton(onClick = { confirmDelete = false }) { Text(stringResource(R.string.cancel)) } },
        )
    }

    emergencyGroups?.let { groups ->
        EmergencyExitDialog(chat.name, groups, onConfirm = onEmergencyExit, onDismiss = onDismissEmergencyExit)
    }
    emergencyResult?.let { result -> EmergencyResultDialog(chat.name, result, onDismiss = onDismissEmergencyExit) }

    if (confirmBlock) {
        AlertDialog(
            onDismissRequest = { confirmBlock = false },
            title = { Text(stringResource(R.string.block_title, chat.name)) },
            text = { Text(stringResource(R.string.block_body, chat.name)) },
            confirmButton = {
                TextButton(onClick = {
                    confirmBlock = false
                    onBlock()
                }) { Text(stringResource(R.string.block), color = MaterialTheme.colorScheme.error) }
            },
            dismissButton = { TextButton(onClick = { confirmBlock = false }) { Text(stringResource(R.string.cancel)) } },
        )
    }

    if (choosingMute) {
        MuteDialog(R.string.mute_contact_explainer, onDismiss = { choosingMute = false }) {
            choosingMute = false
            onMute(it)
        }
    }

    if (editPermissions) {
        PermissionsDialog(
            name = chat.name,
            current = chat.permissions,
            onDismiss = { editPermissions = false },
            onSave = {
                editPermissions = false
                onPermissions(it)
            },
        )
    }
}

/** Push-to-talk: talks while held. */
@Composable
internal fun TalkButton(talking: Boolean, onStart: () -> Boolean, onEnd: () -> Unit) {
    val label = stringResource(R.string.push_to_talk)
    Surface(
        shape = CircleShape,
        color = if (talking) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.primary,
        modifier = Modifier
            .size(52.dp)
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
            Icon(painterResource(R.drawable.ic_mic), contentDescription = null)
        }
    }
}

@StringRes
private fun talkRefusalText(reason: EndReason): Int = when (reason) {
    EndReason.NOT_ALLOWED -> R.string.talk_not_allowed
    EndReason.INTERRUPTED -> R.string.talk_interrupted
    EndReason.BUSY -> R.string.talk_busy
    else -> R.string.call_lost
}

/** In place of the message field: why nothing can be sent to this contact. */
@Composable
private fun InactiveContact(chat: ChatUi, onUnblock: () -> Unit) {
    Surface(color = MaterialTheme.colorScheme.surfaceVariant, modifier = Modifier.fillMaxWidth()) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            val blocked = chat.state == ContactState.BLOCKED
            Text(
                stringResource(if (blocked) R.string.contact_blocked_info else R.string.contact_former_info, chat.name),
                style = MaterialTheme.typography.bodyMedium,
            )
            if (blocked) OutlinedButton(onClick = onUnblock) { Text(stringResource(R.string.unblock)) }
        }
    }
}

/**
 * Confirms the emergency exit from [name]: what this device will do, and whether to also leave the
 * groups shared with them where it is no admin. Says plainly that what was sent stays sent.
 */
@Composable
private fun EmergencyExitDialog(name: String, groups: List<Group>, onConfirm: (Boolean) -> Unit, onDismiss: () -> Unit) {
    val administered = groups.filter { it.admin }
    val others = groups.filterNot { it.admin }
    var leave by remember { mutableStateOf(true) }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(stringResource(R.string.emergency_exit_title, name)) },
        text = {
            Column(Modifier.verticalScroll(rememberScrollState()), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                Text(stringResource(R.string.emergency_exit_block, name))
                Text(stringResource(R.string.emergency_exit_history))
                if (administered.isNotEmpty()) {
                    Text(stringResource(R.string.emergency_exit_admin_groups, administered.joinToString { it.name }))
                }
                if (others.isNotEmpty()) {
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        modifier = Modifier.fillMaxWidth().clickable { leave = !leave },
                    ) {
                        Checkbox(checked = leave, onCheckedChange = { leave = it })
                        Text(
                            stringResource(R.string.emergency_exit_leave, others.joinToString { it.name }),
                            style = MaterialTheme.typography.bodyMedium,
                        )
                    }
                }
                NoticeCard(R.drawable.ic_lock, stringResource(R.string.emergency_exit_limit, name), warning = true)
            }
        },
        confirmButton = {
            TextButton(onClick = { onConfirm(leave && others.isNotEmpty()) }) {
                Text(stringResource(R.string.emergency_exit), color = MaterialTheme.colorScheme.error)
            }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text(stringResource(R.string.cancel)) } },
    )
}

/** What the emergency exit did. */
@Composable
private fun EmergencyResultDialog(name: String, result: EmergencyExit, onDismiss: () -> Unit) {
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(stringResource(R.string.emergency_done_title)) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(stringResource(R.string.emergency_done_contact, name))
                if (result.removedFrom.isNotEmpty()) {
                    Text(stringResource(R.string.emergency_done_removed, result.removedFrom.joinToString()))
                }
                if (result.deleted.isNotEmpty()) {
                    Text(stringResource(R.string.emergency_done_deleted, result.deleted.joinToString()))
                }
                if (result.left.isNotEmpty()) {
                    Text(stringResource(R.string.emergency_done_left, result.left.joinToString()))
                }
                if (result.stillShared.isNotEmpty()) {
                    Text(
                        stringResource(R.string.emergency_done_shared, result.stillShared.joinToString()),
                        color = MaterialTheme.colorScheme.error,
                    )
                }
            }
        },
        confirmButton = { TextButton(onClick = onDismiss) { Text(stringResource(R.string.ok)) } },
    )
}

/** What a contact may do (requirement C-5). */
@Composable
private fun PermissionsDialog(name: String, current: Permissions, onDismiss: () -> Unit, onSave: (Permissions) -> Unit) {
    var messages by remember { mutableStateOf(current.messages) }
    var ptt by remember { mutableStateOf(current.ptt) }
    var autoDownload by remember { mutableStateOf(current.autoDownload) }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(stringResource(R.string.permissions_title, name)) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(16.dp)) {
                PermissionSwitch(R.string.permission_messages, R.string.permission_messages_explainer, messages) { messages = it }
                PermissionSwitch(R.string.permission_ptt, R.string.permission_ptt_explainer, ptt) { ptt = it }
                PermissionSwitch(R.string.permission_auto_download, R.string.permission_auto_download_explainer, autoDownload) {
                    autoDownload = it
                }
            }
        },
        confirmButton = { TextButton(onClick = { onSave(Permissions(messages, ptt, autoDownload)) }) { Text(stringResource(R.string.save)) } },
        dismissButton = { TextButton(onClick = onDismiss) { Text(stringResource(R.string.cancel)) } },
    )
}

@Composable
private fun PermissionSwitch(@StringRes title: Int, @StringRes explainer: Int, checked: Boolean, onChange: (Boolean) -> Unit) {
    Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(12.dp)) {
        Column(Modifier.weight(1f)) {
            Text(stringResource(title), style = MaterialTheme.typography.bodyLarge)
            Text(stringResource(explainer), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
        Switch(checked = checked, onCheckedChange = onChange)
    }
}

@Composable
private fun MessageBubble(
    message: Message,
    tail: Boolean,
    contactName: String,
    contactNearby: Boolean,
    onDownload: () -> Unit,
    onOpen: () -> Unit,
    onTryAgain: () -> Unit,
    playback: VoicePlayback?,
    onToggleVoice: () -> Unit,
) {
    val attachment = message.attachment
    // A message not delivered within a day offers to be tried again on a long press.
    val failed = message.outgoing && message.status == MessageStatus.FAILED
    Bubble(
        outgoing = message.outgoing,
        tail = tail,
        atMs = message.storedAtMs,
        status = { if (message.outgoing) StatusMark(message.status) },
        longPressMenu = if (failed) {
            { close ->
                DropdownMenuItem(
                    text = { Text(stringResource(R.string.message_try_again)) },
                    onClick = {
                        close()
                        onTryAgain()
                    },
                )
            }
        } else {
            null
        },
    ) {
        if (attachment != null && isVoice(attachment)) {
            VoiceContent(attachment, message.outgoing, playback, onToggleVoice)
        } else if (attachment != null) {
            FileContent(message.id, attachment, contactName, contactNearby, onDownload, onOpen)
        } else {
            Text(message.body, style = MaterialTheme.typography.bodyLarge)
        }
    }
}

/** A file: its thumbnail or an icon, name and size, and what can be done with it now. */
@Composable
internal fun FileContent(
    id: Long,
    attachment: Attachment,
    contactName: String,
    contactNearby: Boolean,
    onDownload: () -> Unit,
    onOpen: () -> Unit,
) {
    val context = LocalContext.current
    val size = Formatter.formatShortFileSize(context, attachment.size.toLong())
    val complete = attachment.state == AttachmentState.COMPLETE
    // Decoded in memory from the encrypted database; never cached.
    val thumbnail = remember(id, attachment.thumbnail != null) {
        attachment.thumbnail?.let { BitmapFactory.decodeByteArray(it, 0, it.size)?.asImageBitmap() }
    }
    Column(
        Modifier.widthIn(min = 180.dp).let { if (complete) it.clickable(onClick = onOpen) else it },
        verticalArrangement = Arrangement.spacedBy(6.dp),
    ) {
        if (thumbnail != null) {
            Box(contentAlignment = Alignment.Center) {
                Image(
                    thumbnail,
                    contentDescription = attachment.name,
                    contentScale = ContentScale.Crop,
                    modifier = Modifier
                        .widthIn(max = 260.dp)
                        .aspectRatio(thumbnail.width.toFloat() / thumbnail.height.coerceAtLeast(1))
                        .clip(RoundedCornerShape(12.dp)),
                )
                if (attachment.mime.startsWith("video/")) {
                    Surface(shape = RoundedCornerShape(50), color = MaterialTheme.colorScheme.surface.copy(alpha = 0.8f)) {
                        Icon(painterResource(R.drawable.ic_play), contentDescription = null, modifier = Modifier.padding(8.dp).size(28.dp))
                    }
                }
            }
        }
        Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            if (thumbnail == null) Icon(painterResource(R.drawable.ic_file), contentDescription = null, modifier = Modifier.size(32.dp))
            Column {
                Text(attachment.name, style = MaterialTheme.typography.bodyMedium, maxLines = 2, overflow = TextOverflow.Ellipsis)
                Text(size, style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
        }
        when (attachment.state) {
            AttachmentState.OFFERED -> OutlinedButton(onClick = onDownload) { Text(stringResource(R.string.file_download, size)) }
            AttachmentState.DOWNLOADING -> {
                val total = attachment.size.toLong().coerceAtLeast(1)
                LinearProgressIndicator(
                    progress = { attachment.stored.toLong().toFloat() / total },
                    modifier = Modifier.fillMaxWidth(),
                )
                Text(
                    if (contactNearby) {
                        stringResource(
                            R.string.file_downloading,
                            Formatter.formatShortFileSize(context, attachment.stored.toLong()),
                            size,
                        )
                    } else {
                        stringResource(R.string.file_waiting, contactName)
                    },
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            AttachmentState.FAILED -> {
                Text(stringResource(R.string.file_failed), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
                OutlinedButton(onClick = onDownload) { Text(stringResource(R.string.file_retry)) }
            }
            AttachmentState.GONE ->
                Text(stringResource(R.string.file_gone), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            AttachmentState.COMPLETE -> Unit
        }
    }
}

@Composable
private fun StatusMark(status: MessageStatus) {
    // Until it is acknowledged, a message is being sent: the sender keeps it (rust/airchat-protocol/docs/protocol.md §10.5).
    val (mark, description) = when (status) {
        MessageStatus.QUEUED, MessageStatus.SENT -> "…" to R.string.status_sending
        MessageStatus.DELIVERED -> "✓✓" to R.string.status_delivered
        MessageStatus.REFUSED -> "✕" to R.string.status_refused
        MessageStatus.FAILED -> "!" to R.string.status_failed
        MessageStatus.RECEIVED -> return
    }
    StatusText(
        mark,
        stringResource(description),
        problem = status == MessageStatus.REFUSED || status == MessageStatus.FAILED,
        done = status == MessageStatus.DELIVERED,
    )
}
