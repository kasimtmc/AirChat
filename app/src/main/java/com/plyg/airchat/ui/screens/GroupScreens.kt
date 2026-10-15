package com.plyg.airchat.ui.screens

import android.net.Uri
import androidx.activity.compose.BackHandler
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.PickVisualMediaRequest
import androidx.activity.result.contract.ActivityResultContracts
import androidx.annotation.StringRes
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.consumeWindowInsets
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.text.input.TextFieldLineLimits
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
import androidx.compose.material3.ListItem
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
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
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.compose.material3.ListItemDefaults
import androidx.compose.ui.graphics.Color
import com.plyg.airchat.R
import com.plyg.airchat.ui.VoicePlayback
import com.plyg.airchat.core.Contact
import com.plyg.airchat.core.ContactState
import com.plyg.airchat.core.EndReason
import com.plyg.airchat.core.GroupMember
import com.plyg.airchat.core.GroupMessage
import com.plyg.airchat.core.GroupMessageStatus
import com.plyg.airchat.core.Membership
import com.plyg.airchat.core.groupFile
import com.plyg.airchat.runtime.TalkRefusal
import com.plyg.airchat.runtime.TalkUi
import com.plyg.airchat.ui.GroupChatUi
import androidx.compose.ui.text.font.FontFamily
import java.time.Instant
import java.time.ZoneId
import java.time.format.DateTimeFormatter

private val dateFormat = DateTimeFormatter.ofPattern("d MMM HH:mm")

/** Most members a group has, this device included (rust/airchat-protocol/docs/protocol.md §9.1). */
internal const val MAX_MEMBERS = 32

/** Fewest members a group has: no one can be removed from a group of two (§9.1). */
private const val MIN_MEMBERS = 2

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun GroupChatScreen(
    chat: GroupChatUi,
    /** This device's contacts, to add members from. */
    contacts: List<Contact>,
    error: Int?,
    onSend: (String) -> Unit,
    onBack: () -> Unit,
    onAddMembers: (contactIds: List<Long>, expiresSecs: Long) -> Unit,
    onRemoveMember: (GroupMember) -> Unit,
    onLeave: () -> Unit,
    /** Deletes the group for every member (an admin only). */
    onDeleteForEveryone: () -> Unit = {},
    /** Deletes the conversation of a group this device left or was removed from. */
    onDeleteChat: () -> Unit = {},
    /** Adds members for as long as this device is in the group's call (requirement M-3). */
    onAddMembersForCall: (contactIds: List<Long>) -> Unit = {},
    onSetAdmin: (GroupMember, Boolean) -> Unit = { _, _ -> },
    /** A message no member took within a day is tried again (long press). */
    onTryAgain: (GroupMessage) -> Unit = {},
    /** This device is in the group's call now. */
    inCall: Boolean = false,
    /** Push-to-talk under way, here or elsewhere. */
    talk: TalkUi?,
    /** This device's last talk was cut short. */
    talkRefused: TalkRefusal?,
    /** Pressed: false if talking cannot start (nobody linked, no microphone yet). */
    onTalkStart: () -> Boolean,
    onTalkEnd: () -> Unit,
    onCall: () -> Unit,
    onPtt: (Boolean) -> Unit,
    /** A member is linked now, so files can be fetched. */
    membersNearby: Boolean,
    /** Mutes the group until a time (Unix ms), or unmutes it with 0. */
    onMute: (Long) -> Unit,
    onSendFile: (Uri) -> Unit,
    onDownload: (GroupMessage) -> Unit,
    onOpen: (GroupMessage) -> Unit,
    /** The voice message playing, if one is; a tap plays or pauses one. */
    voicePlayback: VoicePlayback? = null,
    onToggleVoice: (GroupMessage) -> Unit = {},
) {
    BackHandler(onBack = onBack)
    val input = rememberTextFieldState()
    var menu by remember { mutableStateOf(false) }
    var showMembers by remember { mutableStateOf(false) }
    var confirmLeave by remember { mutableStateOf(false) }
    var confirmDelete by remember { mutableStateOf(false) }
    var choosingMute by remember { mutableStateOf(false) }
    // No storage permission needed: the system pickers grant access to what the user picks.
    val pickMedia = rememberLauncherForActivityResult(ActivityResultContracts.PickVisualMedia()) { uri ->
        uri?.let(onSendFile)
    }
    val pickDocument = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        uri?.let(onSendFile)
    }
    val member = chat.group.membership == Membership.MEMBER
    val names = remember(chat.members) { chat.members.associate { it.identity.key() to it } }
    val send = {
        onSend(input.text.toString())
        input.clearText()
    }
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
                    val talkHere = talk?.takeIf { it.groupId == chat.group.id }
                    val talker = talkHere?.let { t -> chat.members.find { it.rowId == t.contactId }?.name }
                    ConversationTitle(
                        name = chat.group.name,
                        title = mutedName(chat.group.name, chat.group.mutedUntil),
                        status = when {
                            talkHere?.voiceMessage == true -> stringResource(R.string.talk_recording_voice)
                            talkHere?.talking == true -> stringResource(R.string.talking)
                            talkHere != null ->
                                stringResource(R.string.contact_talking, talker ?: stringResource(R.string.group_former_member))
                            chat.group.membership == Membership.LEFT -> stringResource(R.string.group_left_label)
                            chat.group.membership == Membership.REMOVED -> stringResource(R.string.group_removed_label)
                            chat.group.membership == Membership.ENDED -> stringResource(R.string.group_ended_label)
                            else -> stringResource(R.string.group_members_count, chat.group.members.toInt())
                        },
                        statusActive = talkHere != null,
                        group = true,
                        nearby = member && membersNearby,
                        modifier = Modifier.clickable { showMembers = true },
                    )
                },
                actions = {
                    if (member) {
                        IconButton(onClick = onCall) {
                            Icon(painterResource(R.drawable.ic_call), contentDescription = stringResource(R.string.group_call))
                        }
                    }
                    Box {
                        val options = stringResource(R.string.group_options)
                        IconButton(onClick = { menu = true }) {
                            Icon(painterResource(R.drawable.ic_more_vert), contentDescription = options)
                        }
                        DropdownMenu(expanded = menu, onDismissRequest = { menu = false }) {
                            DropdownMenuItem(
                                text = { Text(stringResource(R.string.group_members)) },
                                onClick = {
                                    menu = false
                                    showMembers = true
                                },
                            )
                            if (member) {
                                MuteMenuItem(
                                    chat.group.mutedUntil,
                                    onMute = {
                                        menu = false
                                        choosingMute = true
                                    },
                                    onUnmute = {
                                        menu = false
                                        onMute(0)
                                    },
                                )
                                // One tap to accept the group's push-to-talk or not.
                                DropdownMenuItem(
                                    text = {
                                        Column {
                                            Text(stringResource(R.string.permission_ptt))
                                            Text(
                                                stringResource(R.string.group_ptt_explainer),
                                                style = MaterialTheme.typography.bodySmall,
                                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                                            )
                                        }
                                    },
                                    trailingIcon = { Checkbox(checked = chat.group.instantVoice, onCheckedChange = null) },
                                    onClick = {
                                        menu = false
                                        onPtt(!chat.group.instantVoice)
                                    },
                                )
                                DropdownMenuItem(
                                    text = { Text(stringResource(R.string.group_leave), color = MaterialTheme.colorScheme.error) },
                                    onClick = {
                                        menu = false
                                        confirmLeave = true
                                    },
                                )
                            }
                            // An admin deletes the group for everyone; someone no longer in it,
                            // the conversation on this device.
                            if (!member || chat.group.admin) {
                                DropdownMenuItem(
                                    text = {
                                        Text(
                                            stringResource(if (member) R.string.group_delete else R.string.group_delete_chat),
                                            color = MaterialTheme.colorScheme.error,
                                        )
                                    },
                                    onClick = {
                                        menu = false
                                        confirmDelete = true
                                    },
                                )
                            }
                        }
                    }
                },
            )
        },
    ) { padding ->
        // The Scaffold's padding already holds the navigation bar; the keyboard adds what goes past it.
        Column(Modifier.fillMaxSize().padding(padding).consumeWindowInsets(padding).imePadding()) {
            MessageList(
                chat.messages,
                key = { it.id },
                at = { it.storedAtMs },
                // Runs are one sender's: the user's own, or a member's by their key.
                from = { if (it.outgoing) "" else it.sender.key() },
                listState = listState,
                empty = stringResource(R.string.group_no_messages),
                modifier = Modifier.weight(1f).fillMaxWidth(),
            ) { message, first, last ->
                GroupBubble(
                    message,
                    sender = names[message.sender.key()]?.name,
                    showSender = first,
                    tail = last,
                    membersNearby = membersNearby,
                    onDownload = { onDownload(message) },
                    onOpen = { onOpen(message) },
                    onTryAgain = { onTryAgain(message) },
                    playback = voicePlayback?.takeIf { it.file == groupFile(message.id) },
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
                val refusal = talkRefused?.takeIf { it.groupId == chat.group.id }
                val recording = talk?.takeIf { it.voiceMessage && it.groupId == chat.group.id }
                if (error == null && recording != null) {
                    Text(
                        stringResource(R.string.talk_recording_voice_group_hint),
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.primary,
                    )
                } else if (error == null && refusal != null) {
                    Text(
                        stringResource(
                            if (refusal.reason == EndReason.INTERRUPTED) R.string.group_talk_interrupted else R.string.group_talk_not_allowed,
                        ),
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.error,
                    )
                }
            }
            if (!member) {
                Surface(color = MaterialTheme.colorScheme.surfaceVariant, modifier = Modifier.fillMaxWidth()) {
                    Text(
                        stringResource(
                            when (chat.group.membership) {
                                Membership.LEFT -> R.string.group_left_info
                                Membership.ENDED -> R.string.group_ended_info
                                else -> R.string.group_removed_info
                            },
                        ),
                        style = MaterialTheme.typography.bodyMedium,
                        modifier = Modifier.padding(16.dp),
                    )
                }
                return@Column
            }
            MessageInput(
                input,
                onSend = send,
                onPickMedia = { pickMedia.launch(PickVisualMediaRequest(ActivityResultContracts.PickVisualMedia.ImageAndVideo)) },
                onPickFile = { pickDocument.launch(arrayOf("*/*")) },
                talk = { TalkButton(talking = talk?.talking == true && talk.groupId == chat.group.id, onTalkStart, onTalkEnd) },
            )
        }
    }

    if (choosingMute) {
        MuteDialog(R.string.mute_group_explainer, onDismiss = { choosingMute = false }) {
            choosingMute = false
            onMute(it)
        }
    }

    if (showMembers) {
        MembersDialog(
            chat = chat,
            contacts = contacts,
            inCall = inCall,
            onDismiss = { showMembers = false },
            onAdd = onAddMembers,
            onAddForCall = onAddMembersForCall,
            onRemove = onRemoveMember,
            onSetAdmin = onSetAdmin,
        )
    }

    if (confirmDelete) {
        AlertDialog(
            onDismissRequest = { confirmDelete = false },
            title = {
                Text(
                    if (member) {
                        stringResource(R.string.group_delete_title, chat.group.name)
                    } else {
                        stringResource(R.string.group_delete_chat_title, chat.group.name)
                    },
                )
            },
            text = { Text(stringResource(if (member) R.string.group_delete_body else R.string.group_delete_chat_body)) },
            confirmButton = {
                TextButton(onClick = {
                    confirmDelete = false
                    if (member) onDeleteForEveryone() else onDeleteChat()
                }) { Text(stringResource(R.string.delete), color = MaterialTheme.colorScheme.error) }
            },
            dismissButton = { TextButton(onClick = { confirmDelete = false }) { Text(stringResource(R.string.cancel)) } },
        )
    }

    if (confirmLeave) {
        AlertDialog(
            onDismissRequest = { confirmLeave = false },
            title = { Text(stringResource(R.string.group_leave_title, chat.group.name)) },
            text = { Text(stringResource(R.string.group_leave_body)) },
            confirmButton = {
                TextButton(onClick = {
                    confirmLeave = false
                    onLeave()
                }) { Text(stringResource(R.string.group_leave), color = MaterialTheme.colorScheme.error) }
            },
            dismissButton = { TextButton(onClick = { confirmLeave = false }) { Text(stringResource(R.string.cancel)) } },
        )
    }
}

@Composable
private fun GroupBubble(
    message: GroupMessage,
    sender: String?,
    /** The first of a member's run: their name heads it. */
    showSender: Boolean,
    tail: Boolean,
    membersNearby: Boolean,
    onDownload: () -> Unit,
    onOpen: () -> Unit,
    onTryAgain: () -> Unit,
    playback: VoicePlayback?,
    onToggleVoice: () -> Unit,
) {
    val outgoing = message.outgoing
    val senderName = sender ?: stringResource(R.string.group_former_member)
    // A message no member took within a day offers to be tried again on a long press.
    val failed = outgoing && message.status == GroupMessageStatus.FAILED
    Bubble(
        outgoing = outgoing,
        tail = tail,
        atMs = message.storedAtMs,
        status = { if (outgoing) GroupStatusMark(message.status) },
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
        if (!outgoing && showSender) {
            Text(
                senderName,
                style = MaterialTheme.typography.labelLarge,
                // The same color as the member's picture, so a run is told apart at a glance.
                color = if (sender != null) nameColors(sender).second else MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        val attachment = message.attachment
        if (attachment != null && isVoice(attachment)) {
            VoiceContent(attachment, outgoing, playback, onToggleVoice)
        } else if (attachment != null) {
            FileContent(
                groupFile(message.id),
                attachment,
                contactName = senderName,
                contactNearby = membersNearby,
                onDownload = onDownload,
                onOpen = onOpen,
            )
        } else {
            Text(message.body, style = MaterialTheme.typography.bodyLarge)
        }
    }
}

@Composable
private fun GroupStatusMark(status: GroupMessageStatus) {
    val (mark, description) = when (status) {
        GroupMessageStatus.QUEUED -> "…" to R.string.status_sending
        GroupMessageStatus.SENT -> "✓" to R.string.group_status_sent
        GroupMessageStatus.FAILED -> "!" to R.string.status_failed
        GroupMessageStatus.RECEIVED -> return
    }
    StatusText(mark, stringResource(description), problem = status == GroupMessageStatus.FAILED)
}

/** The members; an admin adds and removes them here. */
@Composable
private fun MembersDialog(
    chat: GroupChatUi,
    contacts: List<Contact>,
    inCall: Boolean,
    onDismiss: () -> Unit,
    onAdd: (contactIds: List<Long>, expiresSecs: Long) -> Unit,
    onAddForCall: (contactIds: List<Long>) -> Unit,
    onRemove: (GroupMember) -> Unit,
    onSetAdmin: (GroupMember, Boolean) -> Unit,
) {
    var adding by remember { mutableStateOf(false) }
    var removing by remember { mutableStateOf<GroupMember?>(null) }
    var options by remember { mutableStateOf<GroupMember?>(null) }
    val admin = chat.group.admin
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(stringResource(R.string.group_members)) },
        text = {
            LazyColumn(Modifier.heightIn(max = 420.dp)) {
                items(chat.members.sortedWith(compareBy({ !it.me }, { !it.admin }, { it.name.lowercase() }))) { member ->
                    val details = listOfNotNull(
                        stringResource(R.string.group_you).takeIf { member.me },
                        stringResource(R.string.group_admin).takeIf { member.admin },
                        member.expires.takeIf { it > 0u }?.let { expires ->
                            val until = Instant.ofEpochSecond(expires.toLong()).atZone(ZoneId.systemDefault()).format(dateFormat)
                            stringResource(R.string.group_until, until)
                        },
                    )
                    ListItem(
                        leadingContent = { Avatar(member.name, size = 40.dp) },
                        headlineContent = { Text(member.name) },
                        supportingContent = details.takeIf { it.isNotEmpty() }?.let { { Text(it.joinToString(" · ")) } },
                        trailingContent = if (admin && !member.me) {
                            {
                                IconButton(onClick = { options = member }) {
                                    Icon(
                                        painterResource(R.drawable.ic_more_vert),
                                        contentDescription = stringResource(R.string.group_member_options),
                                    )
                                }
                            }
                        } else {
                            null
                        },
                        colors = ListItemDefaults.colors(containerColor = Color.Transparent),
                    )
                }
            }
        },
        confirmButton = {
            if (admin && chat.group.members.toInt() < MAX_MEMBERS) {
                TextButton(onClick = { adding = true }) { Text(stringResource(R.string.group_add_members)) }
            }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text(stringResource(R.string.close)) } },
    )

    if (adding) {
        val inGroup = chat.members.mapNotNull { it.contactId }.toSet()
        AddMembersDialog(
            candidates = contacts.filter { it.state == ContactState.ACTIVE && it.id !in inGroup },
            room = MAX_MEMBERS - chat.group.members.toInt(),
            inCall = inCall,
            onDismiss = { adding = false },
            onAdd = { ids, expires, forCall ->
                adding = false
                if (forCall) onAddForCall(ids) else onAdd(ids, expires)
            },
        )
    }

    options?.let { member ->
        AlertDialog(
            onDismissRequest = { options = null },
            title = { Text(member.name) },
            text = {
                Column {
                    TextButton(onClick = {
                        options = null
                        onSetAdmin(member, !member.admin)
                    }) {
                        Text(stringResource(if (member.admin) R.string.group_unmake_admin else R.string.group_make_admin))
                    }
                    if (chat.group.members.toInt() > MIN_MEMBERS) {
                        TextButton(onClick = {
                            options = null
                            removing = member
                        }) {
                            Text(stringResource(R.string.group_remove_member), color = MaterialTheme.colorScheme.error)
                        }
                    } else {
                        Text(
                            stringResource(R.string.group_remove_two),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                            modifier = Modifier.padding(horizontal = 12.dp, vertical = 8.dp),
                        )
                    }
                }
            },
            confirmButton = {},
            dismissButton = { TextButton(onClick = { options = null }) { Text(stringResource(R.string.close)) } },
        )
    }

    removing?.let { member ->
        AlertDialog(
            onDismissRequest = { removing = null },
            title = { Text(stringResource(R.string.group_remove_title, member.name)) },
            text = { Text(stringResource(R.string.group_remove_body)) },
            confirmButton = {
                TextButton(onClick = {
                    removing = null
                    onRemove(member)
                }) { Text(stringResource(R.string.group_remove_member), color = MaterialTheme.colorScheme.error) }
            },
            dismissButton = { TextButton(onClick = { removing = null }) { Text(stringResource(R.string.cancel)) } },
        )
    }
}

private enum class Duration(@param:StringRes val label: Int, val seconds: Long) {
    FOREVER(R.string.group_duration_forever, 0),
    /** While this device is in the group's call (12 hours at most). */
    CALL(R.string.group_duration_call, 0),
    HOUR(R.string.group_duration_hour, 3_600),
    DAY(R.string.group_duration_day, 86_400),
    WEEK(R.string.group_duration_week, 7 * 86_400),
}

/** Adds contacts to a group; [inCall] offers "until this call ends", chosen already if [fromCall]. */
@Composable
internal fun AddMembersDialog(
    candidates: List<Contact>,
    /** How many more the group can take. */
    room: Int,
    inCall: Boolean,
    onDismiss: () -> Unit,
    onAdd: (contactIds: List<Long>, expiresSecs: Long, forCall: Boolean) -> Unit,
    fromCall: Boolean = false,
) {
    var picked by remember { mutableStateOf(setOf<Long>()) }
    var duration by remember { mutableStateOf(if (fromCall) Duration.CALL else Duration.FOREVER) }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(stringResource(R.string.group_add_members)) },
        text = {
            if (candidates.isEmpty()) {
                Text(stringResource(R.string.group_all_added))
                return@AlertDialog
            }
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                ContactPicker(candidates, picked, room) { picked = it }
                Text(stringResource(R.string.group_duration), style = MaterialTheme.typography.labelLarge)
                Duration.entries.filter { inCall || it != Duration.CALL }.forEach { option ->
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        modifier = Modifier.fillMaxWidth().selectable(selected = duration == option) { duration = option },
                    ) {
                        RadioButton(selected = duration == option, onClick = null)
                        Text(stringResource(option.label), Modifier.padding(start = 8.dp))
                    }
                }
            }
        },
        confirmButton = {
            TextButton(
                enabled = picked.isNotEmpty(),
                onClick = {
                    val expires = if (duration.seconds == 0L) 0L else System.currentTimeMillis() / 1000 + duration.seconds
                    onAdd(picked.toList(), expires, duration == Duration.CALL)
                },
            ) { Text(stringResource(R.string.group_add_members)) }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text(stringResource(R.string.cancel)) } },
    )
}

/** Creates a group of this device and some of its contacts. */
@Composable
fun NewGroupDialog(contacts: List<Contact>, onDismiss: () -> Unit, onCreate: (name: String, contactIds: List<Long>) -> Unit) {
    val name = rememberTextFieldState()
    var picked by remember { mutableStateOf(setOf<Long>()) }
    val candidates = contacts.filter { it.state == ContactState.ACTIVE }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(stringResource(R.string.new_group)) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                OutlinedTextField(
                    state = name,
                    label = { Text(stringResource(R.string.group_name_hint)) },
                    lineLimits = TextFieldLineLimits.SingleLine,
                    modifier = Modifier.fillMaxWidth(),
                )
                Text(stringResource(R.string.group_pick_members), style = MaterialTheme.typography.labelLarge)
                if (candidates.isEmpty()) {
                    Text(stringResource(R.string.group_pick_none), style = MaterialTheme.typography.bodyMedium)
                } else {
                    ContactPicker(candidates, picked, MAX_MEMBERS - 1) { picked = it }
                }
            }
        },
        confirmButton = {
            TextButton(
                enabled = picked.isNotEmpty() && name.text.isNotBlank(),
                onClick = { onCreate(name.text.toString(), picked.toList()) },
            ) { Text(stringResource(R.string.create)) }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text(stringResource(R.string.cancel)) } },
    )
}

/** Contacts to tick, at most [limit] of them. */
@Composable
internal fun ContactPicker(contacts: List<Contact>, picked: Set<Long>, limit: Int, onChange: (Set<Long>) -> Unit) {
    LazyColumn(Modifier.heightIn(max = 280.dp)) {
        items(contacts, key = { it.id }) { contact ->
            val checked = contact.id in picked
            val enabled = checked || picked.size < limit
            Row(
                verticalAlignment = Alignment.CenterVertically,
                modifier = Modifier
                    .fillMaxWidth()
                    .clickable(enabled = enabled) { onChange(if (checked) picked - contact.id else picked + contact.id) },
            ) {
                Checkbox(checked = checked, onCheckedChange = null, enabled = enabled)
                Text(contact.displayName, Modifier.padding(start = 8.dp, top = 12.dp, bottom = 12.dp))
            }
        }
    }
}

/** A map key for an identity key. */
private fun ByteArray.key(): String = joinToString("") { "%02x".format(it) }

/**
 * Proposes a group of this device, the contact of the conversation and one more contact
 * (requirement M-3, rust/airchat-protocol/docs/protocol.md §9.8); the contact must agree first.
 */
@Composable
fun ProposeMemberDialog(
    ownName: String,
    contactName: String,
    candidates: List<Contact>,
    onDismiss: () -> Unit,
    onPropose: (personId: Long, groupName: String, expiresSecs: Long) -> Unit,
) {
    var picked by remember { mutableStateOf(setOf<Long>()) }
    var duration by remember { mutableStateOf(Duration.FOREVER) }
    val name = rememberTextFieldState()
    val person = candidates.find { it.id in picked }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(stringResource(R.string.propose_member)) },
        text = {
            if (candidates.isEmpty()) {
                Text(stringResource(R.string.group_all_added))
                return@AlertDialog
            }
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(stringResource(R.string.propose_member_explainer, contactName), style = MaterialTheme.typography.bodyMedium)
                ContactPicker(candidates, picked, 1) { picked = it }
                OutlinedTextField(
                    state = name,
                    label = { Text(stringResource(R.string.group_name_hint)) },
                    placeholder = { Text(listOfNotNull(ownName, contactName, person?.displayName).joinToString(", ")) },
                    lineLimits = TextFieldLineLimits.SingleLine,
                    modifier = Modifier.fillMaxWidth(),
                )
                Text(stringResource(R.string.group_duration), style = MaterialTheme.typography.labelLarge)
                Duration.entries.filter { it != Duration.CALL }.forEach { option ->
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        modifier = Modifier.fillMaxWidth().selectable(selected = duration == option) { duration = option },
                    ) {
                        RadioButton(selected = duration == option, onClick = null)
                        Text(stringResource(option.label), Modifier.padding(start = 8.dp))
                    }
                }
            }
        },
        confirmButton = {
            TextButton(
                enabled = person != null,
                onClick = {
                    val chosen = person ?: return@TextButton
                    val groupName = name.text.toString().trim()
                        .ifEmpty { listOf(ownName, contactName, chosen.displayName).joinToString(", ") }
                    val expires = if (duration.seconds == 0L) 0L else System.currentTimeMillis() / 1000 + duration.seconds
                    onPropose(chosen.id, groupName, expires)
                },
            ) { Text(stringResource(R.string.propose_member_send)) }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text(stringResource(R.string.cancel)) } },
    )
}

/** A contact's proposal to add someone to your conversation as a group of three (M-3). */
@Composable
fun MemberProposalDialog(asked: com.plyg.airchat.ui.ProposalUi, onAnswer: (Boolean) -> Unit) {
    val proposal = asked.proposal
    AlertDialog(
        onDismissRequest = {},
        title = { Text(stringResource(R.string.member_proposal_title, asked.contactName)) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(stringResource(R.string.member_proposal_body, asked.contactName, proposal.personName, proposal.groupName))
                Text(proposal.personAirchatId, fontFamily = FontFamily.Monospace)
                if (proposal.expires > 0u) {
                    val until = Instant.ofEpochSecond(proposal.expires.toLong()).atZone(ZoneId.systemDefault()).format(dateFormat)
                    Text(stringResource(R.string.group_until, until), style = MaterialTheme.typography.bodySmall)
                }
            }
        },
        confirmButton = { TextButton(onClick = { onAnswer(true) }) { Text(stringResource(R.string.member_proposal_agree)) } },
        dismissButton = { TextButton(onClick = { onAnswer(false) }) { Text(stringResource(R.string.decline_request)) } },
    )
}

