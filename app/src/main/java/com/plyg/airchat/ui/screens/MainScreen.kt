package com.plyg.airchat.ui.screens

import android.content.ClipData
import androidx.activity.compose.BackHandler
import androidx.annotation.StringRes
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.input.TextFieldLineLimits
import androidx.compose.foundation.text.input.clearText
import androidx.compose.foundation.text.input.rememberTextFieldState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FloatingActionButton
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TextField
import androidx.compose.material3.TextFieldDefaults
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.ClipEntry
import androidx.compose.ui.platform.LocalClipboard
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.plyg.airchat.BuildConfig
import com.plyg.airchat.R
import com.plyg.airchat.core.ChatPreview
import com.plyg.airchat.core.Contact
import com.plyg.airchat.core.ContactRequest
import com.plyg.airchat.core.ContactState
import com.plyg.airchat.core.Group
import com.plyg.airchat.core.Membership
import com.plyg.airchat.core.PreviewStatus
import com.plyg.airchat.core.coreVersion
import com.plyg.airchat.core.protocolVersion
import com.plyg.airchat.net.TransportKind
import com.plyg.airchat.net.WifiCheck
import com.plyg.airchat.ui.HomeTab
import com.plyg.airchat.ui.Screen
import com.plyg.airchat.ui.UiState
import com.plyg.airchat.ui.label
import kotlinx.coroutines.launch

/**
 * The main screen, as messaging apps have it: the chats, the walkie-talkie and the settings, as tabs.
 */
@Composable
fun MainScreen(
    state: UiState,
    home: Screen.Home,
    onSelectTab: (HomeTab) -> Unit,
    onLock: () -> Unit,
    onAddNearby: () -> Unit,
    onOpenChat: (Contact) -> Unit,
    onOpenGroup: (Group) -> Unit,
    onCreateGroup: (name: String, contactIds: List<Long>) -> Unit,
    onRequestContact: (String) -> Unit,
    onCancelRequest: (String) -> Unit,
    onApproveRequest: (ContactRequest) -> Unit,
    onDeclineRequest: (ContactRequest) -> Unit,
    onDismissRequestError: () -> Unit,
    onBiometricChange: (Boolean) -> Unit,
    onReceiveWhileLockedChange: (Boolean) -> Unit,
    onAcceptRequestsChange: (Boolean) -> Unit,
    onAirProviderChange: (Boolean) -> Unit,
    onCheckWifi: suspend () -> WifiCheck.Result,
    onTransportChange: (TransportKind, Boolean) -> Unit,
    onDirectContactLinksChange: (Boolean) -> Unit,
    /** The walkie-talkie tab, as its own screen draws it. */
    walkie: @Composable () -> Unit,
) {
    // Back from another tab goes to the chats, as in other messaging apps.
    BackHandler(enabled = state.homeTab != HomeTab.CHATS) { onSelectTab(HomeTab.CHATS) }
    Scaffold(
        bottomBar = {
            NavigationBar {
                val unread = state.previews.sumOf { it.unread.toInt() }
                TabItem(state.homeTab, HomeTab.CHATS, R.drawable.ic_chat, R.string.tab_chats, onSelectTab, badge = unread)
                TabItem(state.homeTab, HomeTab.WALKIE, R.drawable.ic_walkie, R.string.walkie, onSelectTab)
                TabItem(state.homeTab, HomeTab.SETTINGS, R.drawable.ic_settings, R.string.tab_settings, onSelectTab)
            }
        },
    ) { padding ->
        Box(Modifier.fillMaxSize().padding(bottom = padding.calculateBottomPadding())) {
            when (state.homeTab) {
                HomeTab.CHATS -> ChatsTab(
                    state, onLock, onAddNearby, onOpenChat, onOpenGroup, onCreateGroup, onRequestContact,
                    onCancelRequest, onApproveRequest, onDeclineRequest, onDismissRequestError,
                )
                HomeTab.WALKIE -> walkie()
                HomeTab.SETTINGS -> SettingsTab(
                    state, home, onLock, onOpenChat, onBiometricChange, onReceiveWhileLockedChange,
                    onAcceptRequestsChange, onAirProviderChange, onCheckWifi, onTransportChange, onDirectContactLinksChange,
                )
            }
        }
    }
}

@Composable
private fun androidx.compose.foundation.layout.RowScope.TabItem(
    selected: HomeTab,
    tab: HomeTab,
    icon: Int,
    @StringRes label: Int,
    onSelect: (HomeTab) -> Unit,
    badge: Int = 0,
) {
    NavigationBarItem(
        selected = selected == tab,
        onClick = { onSelect(tab) },
        icon = {
            Box {
                Icon(painterResource(icon), contentDescription = null)
                if (badge > 0) {
                    UnreadBadge(badge, Modifier.align(Alignment.TopEnd).padding(start = 16.dp))
                }
            }
        },
        label = { Text(stringResource(label)) },
    )
}

@Composable
private fun UnreadBadge(count: Int, modifier: Modifier = Modifier) {
    Surface(color = MaterialTheme.colorScheme.primary, shape = CircleShape, modifier = modifier) {
        Text(
            if (count > 99) "99+" else count.toString(),
            color = MaterialTheme.colorScheme.onPrimary,
            style = MaterialTheme.typography.labelSmall,
            modifier = Modifier.padding(horizontal = 6.dp, vertical = 1.dp),
        )
    }
}

/** A conversation in the list: a contact's or a group's. */
private class ChatItem(val key: String, val name: String, val contact: Contact?, val group: Group?, val preview: ChatPreview?) {
    /** The latest message's time; a conversation without any sorts by when the contact was added. */
    val sortAt: Long = preview?.last?.atMs ?: contact?.addedAtMs ?: 0
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun ChatsTab(
    state: UiState,
    onLock: () -> Unit,
    onAddNearby: () -> Unit,
    onOpenChat: (Contact) -> Unit,
    onOpenGroup: (Group) -> Unit,
    onCreateGroup: (name: String, contactIds: List<Long>) -> Unit,
    onRequestContact: (String) -> Unit,
    onCancelRequest: (String) -> Unit,
    onApproveRequest: (ContactRequest) -> Unit,
    onDeclineRequest: (ContactRequest) -> Unit,
    onDismissRequestError: () -> Unit,
) {
    var newMenu by remember { mutableStateOf(false) }
    var newGroup by remember { mutableStateOf(false) }
    var addById by remember { mutableStateOf(false) }
    var requests by remember { mutableStateOf(false) }
    var searching by remember { mutableStateOf(false) }
    val query = rememberTextFieldState()
    val byContact = state.previews.filter { it.contactId != null }.associateBy { it.contactId }
    val byGroup = state.previews.filter { it.groupId != null }.associateBy { it.groupId }
    // Blocked contacts are listed in the settings, not among the chats.
    val items = (
        state.contacts.filter { it.state != ContactState.BLOCKED }
            .map { ChatItem("c${it.id}", it.displayName, it, null, byContact[it.id]) } +
            state.groups.map { ChatItem("g${it.id}", it.name, null, it, byGroup[it.id]) }
        ).sortedByDescending { it.sortAt }
    val needle = query.text.toString().trim()
    val shown = if (searching && needle.isNotEmpty()) items.filter { it.name.contains(needle, ignoreCase = true) } else items
    Scaffold(
        topBar = {
            TopAppBar(
                title = {
                    if (searching) {
                        TextField(
                            state = query,
                            placeholder = { Text(stringResource(R.string.search_chats)) },
                            lineLimits = TextFieldLineLimits.SingleLine,
                            colors = TextFieldDefaults.colors(
                                focusedContainerColor = Color.Transparent,
                                unfocusedContainerColor = Color.Transparent,
                            ),
                            modifier = Modifier.fillMaxWidth(),
                        )
                    } else {
                        Text(stringResource(R.string.app_name), fontWeight = FontWeight.Medium)
                    }
                },
                navigationIcon = {
                    if (searching) {
                        IconButton(onClick = {
                            searching = false
                            query.clearText()
                        }) { Icon(painterResource(R.drawable.ic_back), contentDescription = stringResource(R.string.back)) }
                    }
                },
                actions = {
                    if (searching && query.text.isNotEmpty()) {
                        IconButton(onClick = { query.clearText() }) {
                            Icon(painterResource(R.drawable.ic_close), contentDescription = stringResource(R.string.close))
                        }
                    }
                    if (!searching) {
                        IconButton(onClick = { searching = true }) {
                            Icon(painterResource(R.drawable.ic_search), contentDescription = stringResource(R.string.search_chats))
                        }
                        IconButton(onClick = onLock) {
                            Icon(painterResource(R.drawable.ic_lock), contentDescription = stringResource(R.string.lock))
                        }
                    }
                },
            )
        },
        floatingActionButton = {
            Box {
                FloatingActionButton(onClick = { newMenu = true }) {
                    Icon(painterResource(R.drawable.ic_add), contentDescription = stringResource(R.string.new_chat))
                }
                DropdownMenu(expanded = newMenu, onDismissRequest = { newMenu = false }) {
                    DropdownMenuItem(
                        text = { Text(stringResource(R.string.add_nearby)) },
                        leadingIcon = { Icon(painterResource(R.drawable.ic_person_add), contentDescription = null) },
                        onClick = {
                            newMenu = false
                            onAddNearby()
                        },
                    )
                    DropdownMenuItem(
                        text = { Text(stringResource(R.string.add_by_id)) },
                        leadingIcon = { Icon(painterResource(R.drawable.ic_qr), contentDescription = null) },
                        onClick = {
                            newMenu = false
                            addById = true
                        },
                    )
                    DropdownMenuItem(
                        text = { Text(stringResource(R.string.new_group)) },
                        leadingIcon = { Icon(painterResource(R.drawable.ic_group), contentDescription = null) },
                        onClick = {
                            newMenu = false
                            newGroup = true
                        },
                    )
                }
            }
        },
    ) { padding ->
        LazyColumn(Modifier.fillMaxSize().padding(padding), contentPadding = PaddingValues(bottom = 88.dp)) {
            items(problems(state)) { problem -> Banner(stringResource(problem), error = true) }
            if (!searching && (state.contactRequests.isNotEmpty() || state.sentRequests.isNotEmpty())) {
                item {
                    val text = if (state.contactRequests.isNotEmpty()) {
                        pluralStringResource(R.plurals.requests_waiting, state.contactRequests.size, state.contactRequests.size)
                    } else {
                        pluralStringResource(R.plurals.requests_sent, state.sentRequests.size, state.sentRequests.size)
                    }
                    Banner(text, icon = R.drawable.ic_person_add, onClick = { requests = true })
                }
            }
            if (items.isEmpty()) {
                item { EmptyChats(onAddNearby = onAddNearby, onAddById = { addById = true }) }
            }
            items(shown, key = { it.key }) { item ->
                ChatRow(item, nearby = item.contact?.id?.let { it in state.linked } == true) {
                    item.contact?.let(onOpenChat) ?: item.group?.let(onOpenGroup)
                }
            }
        }
    }
    if (requests) {
        RequestsDialog(
            requests = state.contactRequests,
            sent = state.sentRequests,
            onApprove = onApproveRequest,
            onDecline = onDeclineRequest,
            onWithdraw = onCancelRequest,
            onDismiss = { requests = false },
        )
    }
    if (addById) {
        AddByIdDialog(
            onDismiss = { addById = false },
            onSend = { id ->
                onRequestContact(id)
                addById = false
            },
        )
    }
    state.requestError?.let { error ->
        AlertDialog(
            onDismissRequest = onDismissRequestError,
            text = { Text(stringResource(error)) },
            confirmButton = { TextButton(onClick = onDismissRequestError) { Text(stringResource(R.string.ok)) } },
        )
    }
    if (newGroup) {
        NewGroupDialog(
            contacts = state.contacts,
            onDismiss = { newGroup = false },
            onCreate = { name, ids ->
                newGroup = false
                onCreateGroup(name, ids)
            },
        )
    }
}

/** What keeps AirChat from reaching others: permissions missing, Bluetooth off. */
private fun problems(state: UiState): List<Int> = listOfNotNull(
    R.string.network_permission_needed.takeIf { !state.networkAllowed },
    R.string.bluetooth_permission_needed.takeIf { !state.bluetoothAllowed },
    R.string.bluetooth_off.takeIf { state.bluetoothAllowed && !state.bluetoothOn },
    R.string.wifi_permission_needed.takeIf { !state.wifiAllowed },
)

/** A strip across the top of a list: a problem, or something to look at. */
@Composable
private fun Banner(text: String, error: Boolean = false, icon: Int? = null, onClick: (() -> Unit)? = null) {
    val colors = MaterialTheme.colorScheme
    Surface(
        color = if (error) colors.errorContainer else colors.primaryContainer,
        contentColor = if (error) colors.onErrorContainer else colors.onPrimaryContainer,
        shape = RoundedCornerShape(12.dp),
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 12.dp, vertical = 4.dp)
            .let { if (onClick != null) it.clickable(onClick = onClick) else it },
    ) {
        Row(Modifier.padding(horizontal = 12.dp, vertical = 10.dp), verticalAlignment = Alignment.CenterVertically) {
            if (icon != null) {
                Icon(painterResource(icon), contentDescription = null, modifier = Modifier.size(20.dp))
                Spacer(Modifier.width(10.dp))
            }
            Text(text, style = MaterialTheme.typography.bodyMedium, modifier = Modifier.weight(1f))
        }
    }
}

@Composable
private fun EmptyChats(onAddNearby: () -> Unit, onAddById: () -> Unit) {
    Column(
        Modifier.fillMaxWidth().padding(horizontal = 32.dp, vertical = 48.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Icon(
            painterResource(R.drawable.ic_chat),
            contentDescription = null,
            tint = MaterialTheme.colorScheme.primary,
            modifier = Modifier.size(56.dp),
        )
        Text(stringResource(R.string.chats_empty_title), style = MaterialTheme.typography.titleLarge)
        Text(
            stringResource(R.string.chats_empty_body),
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Button(onClick = onAddNearby) { Text(stringResource(R.string.add_nearby)) }
        OutlinedButton(onClick = onAddById) { Text(stringResource(R.string.add_by_id)) }
    }
}

@Composable
private fun ChatRow(item: ChatItem, nearby: Boolean, onClick: () -> Unit) {
    val last = item.preview?.last
    val unread = item.preview?.unread?.toInt() ?: 0
    val muted = isMuted(item.contact?.mutedUntil ?: item.group?.mutedUntil ?: 0)
    Row(
        Modifier.fillMaxWidth().clickable(onClick = onClick).padding(horizontal = 16.dp, vertical = 10.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Avatar(item.name, group = item.group != null, nearby = nearby)
        Spacer(Modifier.width(14.dp))
        Column(Modifier.weight(1f)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(
                    item.name,
                    style = MaterialTheme.typography.titleMedium,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                    modifier = Modifier.weight(1f),
                )
                if (last != null) {
                    Text(
                        chatTime(last.atMs),
                        style = MaterialTheme.typography.labelMedium,
                        color = if (unread > 0) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(
                    previewText(item),
                    style = MaterialTheme.typography.bodyMedium,
                    color = if (last?.status == PreviewStatus.FAILED) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                    modifier = Modifier.weight(1f),
                )
                if (muted) Text("🔕", style = MaterialTheme.typography.labelMedium, modifier = Modifier.padding(start = 4.dp))
                if (unread > 0) UnreadBadge(unread, Modifier.padding(start = 6.dp))
            }
        }
    }
}

/** The second line of a chat in the list: its latest message, or where it stands. */
@Composable
private fun previewText(item: ChatItem): String {
    val last = item.preview?.last
    val state = when {
        item.contact?.state == ContactState.FORMER -> stringResource(R.string.contact_former_label)
        item.group?.membership == Membership.LEFT -> stringResource(R.string.group_left_label)
        item.group?.membership == Membership.REMOVED -> stringResource(R.string.group_removed_label)
        item.group?.membership == Membership.ENDED -> stringResource(R.string.group_ended_label)
        else -> null
    }
    if (last == null) {
        return state ?: if (item.group != null) {
            stringResource(R.string.group_members_count, item.group.members.toInt())
        } else {
            stringResource(R.string.no_messages_yet)
        }
    }
    val content = when {
        last.voice -> "🎤 " + stringResource(R.string.voice_message)
        else -> last.fileName?.let { "📎 $it" } ?: last.body
    }
    val prefix = when {
        last.outgoing -> when (last.status) {
            PreviewStatus.SENDING -> "… "
            PreviewStatus.SENT -> "✓ "
            PreviewStatus.DELIVERED -> "✓✓ "
            PreviewStatus.FAILED -> "! "
            PreviewStatus.REFUSED -> "✕ "
            PreviewStatus.RECEIVED -> ""
        }
        else -> last.senderName?.let { "${it.ifEmpty { stringResource(R.string.group_former_member) }}: " } ?: ""
    }
    return listOfNotNull(state, "$prefix$content").joinToString(" · ")
}

/** People who asked to be added, and the IDs this user typed. */
@Composable
private fun RequestsDialog(
    requests: List<ContactRequest>,
    sent: List<String>,
    onApprove: (ContactRequest) -> Unit,
    onDecline: (ContactRequest) -> Unit,
    onWithdraw: (String) -> Unit,
    onDismiss: () -> Unit,
) {
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(stringResource(R.string.contact_requests)) },
        text = {
            LazyColumn(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                items(requests, key = { "r-${it.airchatId}" }) { request ->
                    Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Avatar(request.displayName, size = 36.dp)
                            Spacer(Modifier.width(10.dp))
                            Column(Modifier.weight(1f)) {
                                Text(request.displayName, style = MaterialTheme.typography.titleSmall)
                                Text(request.airchatId, fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.bodySmall)
                            }
                        }
                        Text(
                            stringResource(R.string.contact_request_explainer),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.End) {
                            TextButton(onClick = { onDecline(request) }) { Text(stringResource(R.string.decline_request)) }
                            TextButton(onClick = { onApprove(request) }) { Text(stringResource(R.string.approve_request)) }
                        }
                        HorizontalDivider()
                    }
                }
                if (sent.isNotEmpty()) {
                    item {
                        Text(
                            stringResource(R.string.sent_requests),
                            style = MaterialTheme.typography.titleSmall,
                            modifier = Modifier.padding(top = 4.dp),
                        )
                    }
                }
                items(sent, key = { "s-$it" }) { id ->
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Column(Modifier.weight(1f)) {
                            Text(id, fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.bodySmall)
                            Text(
                                stringResource(R.string.sent_request_waiting),
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                            )
                        }
                        TextButton(onClick = { onWithdraw(id) }) { Text(stringResource(R.string.withdraw)) }
                    }
                }
            }
        },
        confirmButton = { TextButton(onClick = onDismiss) { Text(stringResource(R.string.close)) } },
    )
}

/** Asks for an AirChat ID to send a contact request to (rust/airchat-protocol/docs/protocol.md §4.8). */
@Composable
private fun AddByIdDialog(onDismiss: () -> Unit, onSend: (String) -> Unit) {
    val id = rememberTextFieldState()
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(stringResource(R.string.add_by_id)) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(stringResource(R.string.add_by_id_explainer), style = MaterialTheme.typography.bodyMedium)
                OutlinedTextField(
                    state = id,
                    placeholder = { Text("AIR-XXXXX-XXXXX-XXXXX-XXXXX-XXXXX", fontFamily = FontFamily.Monospace) },
                    lineLimits = TextFieldLineLimits.SingleLine,
                    textStyle = MaterialTheme.typography.bodyLarge.copy(fontFamily = FontFamily.Monospace),
                    modifier = Modifier.fillMaxWidth(),
                )
            }
        },
        confirmButton = {
            TextButton(enabled = id.text.isNotBlank(), onClick = { onSend(id.text.toString()) }) {
                Text(stringResource(R.string.send_request))
            }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text(stringResource(R.string.cancel)) } },
    )
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun SettingsTab(
    state: UiState,
    home: Screen.Home,
    onLock: () -> Unit,
    onOpenChat: (Contact) -> Unit,
    onBiometricChange: (Boolean) -> Unit,
    onReceiveWhileLockedChange: (Boolean) -> Unit,
    onAcceptRequestsChange: (Boolean) -> Unit,
    onAirProviderChange: (Boolean) -> Unit,
    onCheckWifi: suspend () -> WifiCheck.Result,
    onTransportChange: (TransportKind, Boolean) -> Unit,
    onDirectContactLinksChange: (Boolean) -> Unit,
) {
    var confirmAirProvider by remember { mutableStateOf(false) }
    var checkingWifi by remember { mutableStateOf(false) }
    val clipboard = LocalClipboard.current
    val scope = rememberCoroutineScope()
    val snackbar = remember { SnackbarHostState() }
    val copied = stringResource(R.string.id_copied)
    Scaffold(
        topBar = { TopAppBar(title = { Text(stringResource(R.string.tab_settings), fontWeight = FontWeight.Medium) }) },
        snackbarHost = { SnackbarHost(snackbar) },
    ) { padding ->
        LazyColumn(Modifier.fillMaxSize().padding(padding), contentPadding = PaddingValues(bottom = 24.dp)) {
            item {
                Row(Modifier.fillMaxWidth().padding(16.dp), verticalAlignment = Alignment.CenterVertically) {
                    Avatar(home.displayName, size = 64.dp)
                    Spacer(Modifier.width(16.dp))
                    Column(Modifier.weight(1f)) {
                        Text(home.displayName, style = MaterialTheme.typography.titleLarge)
                        Text(
                            home.airchatId,
                            fontFamily = FontFamily.Monospace,
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                    IconButton(onClick = {
                        scope.launch {
                            clipboard.setClipEntry(ClipEntry(ClipData.newPlainText("AirChat ID", home.airchatId)))
                            snackbar.showSnackbar(copied)
                        }
                    }) { Icon(painterResource(R.drawable.ic_copy), contentDescription = stringResource(R.string.copy_id)) }
                }
                Text(
                    stringResource(R.string.airchat_id_explainer),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.padding(horizontal = 16.dp),
                )
            }
            items(problems(state)) { problem -> Banner(stringResource(problem), error = true) }

            item { Section(R.string.settings_privacy) }
            if (state.biometricAvailable) {
                item {
                    SwitchRow(stringResource(R.string.biometric_unlock), null, state.biometricEnabled, onBiometricChange, enabled = !state.busy)
                }
            }
            item {
                SwitchRow(
                    stringResource(R.string.receive_while_locked),
                    stringResource(R.string.receive_while_locked_explainer),
                    state.receiveWhileLocked,
                    onReceiveWhileLockedChange,
                )
            }
            item {
                SwitchRow(
                    stringResource(R.string.accept_requests),
                    stringResource(R.string.accept_requests_explainer),
                    state.acceptRequests,
                    onAcceptRequestsChange,
                )
            }
            item { ActionRow(stringResource(R.string.lock_now), R.drawable.ic_lock, onLock) }

            item { Section(R.string.settings_network) }
            item {
                val provider = state.airProvider
                // Not offered without Wi-Fi Aware (AP-1); the user is told why.
                if (!provider.supported) {
                    Column(Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 10.dp)) {
                        Text(stringResource(R.string.air_provider), style = MaterialTheme.typography.bodyLarge)
                        Text(
                            stringResource(R.string.air_provider_unsupported),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                    return@item
                }
                SwitchRow(
                    stringResource(R.string.air_provider),
                    when {
                        provider.enabled && provider.classes.size > 1 -> stringResource(R.string.air_provider_carrying_all)
                        provider.enabled -> stringResource(R.string.air_provider_carrying_voice, provider.batteryPercent)
                        provider.hot -> stringResource(R.string.air_provider_hot)
                        provider.cannotRun -> stringResource(R.string.air_provider_low_battery, provider.batteryPercent)
                        else -> stringResource(R.string.air_provider_explainer)
                    },
                    provider.enabled,
                    { on -> if (on) confirmAirProvider = true else onAirProviderChange(false) },
                    enabled = provider.enabled || !provider.cannotRun,
                )
            }
            item {
                // The mesh (protocol §10): how many AirChat devices pass messages on with this one.
                val mesh = if (state.meshNeighbours == 0) {
                    stringResource(R.string.mesh_alone)
                } else {
                    pluralStringResource(R.plurals.mesh_neighbours, state.meshNeighbours, state.meshNeighbours)
                }
                val providers = if (state.providers > 0) {
                    pluralStringResource(R.plurals.air_providers_nearby, state.providers, state.providers)
                } else {
                    null
                }
                InfoRow(listOfNotNull(mesh, providers).joinToString("\n"))
            }
            item { ActionRow(stringResource(R.string.wifi_check), R.drawable.ic_wifi) { checkingWifi = true } }

            val blocked = state.contacts.filter { it.state == ContactState.BLOCKED }
            if (blocked.isNotEmpty()) {
                item { Section(R.string.settings_blocked) }
                items(blocked, key = { "b${it.id}" }) { contact ->
                    Row(
                        Modifier.fillMaxWidth().clickable { onOpenChat(contact) }.padding(horizontal = 16.dp, vertical = 8.dp),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Avatar(contact.displayName, size = 36.dp)
                        Spacer(Modifier.width(12.dp))
                        Text(contact.displayName, style = MaterialTheme.typography.bodyLarge, modifier = Modifier.weight(1f))
                    }
                }
            }

            item { Section(R.string.settings_about) }
            item { InfoRow(stringResource(R.string.core_info, coreVersion(), protocolVersion().toInt())) }

            if (BuildConfig.DEBUG) {
                item { Section(R.string.settings_debug) }
                // The hotspot is opened on demand, and paths through Air Providers run over the others.
                items(TransportKind.entries - TransportKind.HOTSPOT - TransportKind.RELAY) { kind ->
                    SwitchRow(
                        stringResource(R.string.debug_transport, stringResource(kind.label)),
                        null,
                        kind !in state.disabledTransports,
                        { onTransportChange(kind, it) },
                    )
                }
                item {
                    SwitchRow(stringResource(R.string.debug_direct_contact_links), null, state.directContactLinks, onDirectContactLinksChange)
                }
            }
            item { Box(Modifier.padding(horizontal = 16.dp)) { ErrorText(state.error) } }
        }
    }
    if (confirmAirProvider) {
        // Requirement AP-5: the battery warning comes before the mode goes on.
        AlertDialog(
            onDismissRequest = { confirmAirProvider = false },
            title = { Text(stringResource(R.string.air_provider)) },
            text = { Text(stringResource(R.string.air_provider_warning)) },
            confirmButton = {
                TextButton(onClick = {
                    confirmAirProvider = false
                    onAirProviderChange(true)
                }) { Text(stringResource(R.string.air_provider_turn_on)) }
            },
            dismissButton = { TextButton(onClick = { confirmAirProvider = false }) { Text(stringResource(R.string.cancel)) } },
        )
    }
    if (checkingWifi) WifiCheckDialog(onCheckWifi, onDismiss = { checkingWifi = false })
}

/** The Wi-Fi check (requirements AP-10), and what a router's owner can do about its answer. */
@Composable
private fun WifiCheckDialog(check: suspend () -> WifiCheck.Result, onDismiss: () -> Unit) {
    var result by remember { mutableStateOf<WifiCheck.Result?>(null) }
    LaunchedEffect(Unit) { result = check() }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(stringResource(R.string.wifi_check)) },
        text = {
            Column(Modifier.verticalScroll(rememberScrollState())) {
                when (result) {
                    null -> Row(verticalAlignment = Alignment.CenterVertically) {
                        CircularProgressIndicator(Modifier.size(20.dp), strokeWidth = 2.dp)
                        Spacer(Modifier.width(12.dp))
                        Text(stringResource(R.string.wifi_check_running))
                    }
                    WifiCheck.Result.NO_WIFI -> Text(stringResource(R.string.wifi_check_no_wifi))
                    WifiCheck.Result.WORKS -> Text(stringResource(R.string.wifi_check_works))
                    WifiCheck.Result.DEVICES_HEARD -> Text(stringResource(R.string.wifi_check_heard))
                    WifiCheck.Result.NONE_HEARD -> {
                        Text(stringResource(R.string.wifi_check_none))
                        Spacer(Modifier.height(12.dp))
                        Text(stringResource(R.string.wifi_guide_title), style = MaterialTheme.typography.titleSmall)
                        Text(stringResource(R.string.wifi_guide))
                    }
                }
                Spacer(Modifier.height(12.dp))
                Text(
                    stringResource(R.string.wifi_check_private),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        },
        confirmButton = { TextButton(onClick = onDismiss) { Text(stringResource(R.string.close)) } },
    )
}

@Composable
private fun Section(@StringRes title: Int) {
    Text(
        stringResource(title),
        style = MaterialTheme.typography.labelLarge,
        color = MaterialTheme.colorScheme.primary,
        modifier = Modifier.padding(start = 16.dp, end = 16.dp, top = 20.dp, bottom = 4.dp),
    )
}

@Composable
private fun SwitchRow(title: String, subtitle: String?, checked: Boolean, onChange: (Boolean) -> Unit, enabled: Boolean = true) {
    Row(
        Modifier
            .fillMaxWidth()
            .clickable(enabled = enabled) { onChange(!checked) }
            .padding(horizontal = 16.dp, vertical = 10.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Column(Modifier.weight(1f).padding(end = 12.dp)) {
            Text(title, style = MaterialTheme.typography.bodyLarge)
            if (subtitle != null) {
                Text(subtitle, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
        }
        Switch(checked = checked, onCheckedChange = onChange, enabled = enabled)
    }
}

@Composable
private fun ActionRow(title: String, icon: Int, onClick: () -> Unit) {
    Row(
        Modifier.fillMaxWidth().clickable(onClick = onClick).padding(horizontal = 16.dp, vertical = 14.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text(title, style = MaterialTheme.typography.bodyLarge, modifier = Modifier.weight(1f))
        Icon(painterResource(icon), contentDescription = null, tint = MaterialTheme.colorScheme.onSurfaceVariant)
    }
}

@Composable
private fun InfoRow(text: String) {
    Text(
        text,
        style = MaterialTheme.typography.bodyMedium,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
        modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 8.dp),
    )
}
