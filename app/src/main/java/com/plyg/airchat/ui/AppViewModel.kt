package com.plyg.airchat.ui

import android.Manifest
import android.app.Application
import android.content.pm.PackageManager
import android.media.MediaDataSource
import android.net.Uri
import android.os.Build
import android.os.SystemClock
import android.provider.DocumentsContract
import android.util.Log
import androidx.annotation.StringRes
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.graphics.asImageBitmap
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import androidx.core.content.ContextCompat
import com.plyg.airchat.AirChatApplication
import com.plyg.airchat.BuildConfig
import com.plyg.airchat.R
import com.plyg.airchat.core.EmergencyExit
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.MutableStateFlow
import java.time.format.DateTimeFormatter
import java.time.LocalDateTime
import com.plyg.airchat.runtime.VoiceMessage
import com.plyg.airchat.core.voiceMime
import android.media.MediaPlayer
import android.media.AudioAttributes
import com.plyg.airchat.account.AccountStore
import com.plyg.airchat.core.Account
import com.plyg.airchat.core.Action
import com.plyg.airchat.core.Attachment
import com.plyg.airchat.core.AttachmentState
import com.plyg.airchat.core.ChannelPeer
import com.plyg.airchat.core.Contact
import com.plyg.airchat.core.ChatPreview
import com.plyg.airchat.core.ContactRequest
import com.plyg.airchat.core.ContactState
import com.plyg.airchat.core.CoreException
import com.plyg.airchat.core.Failure
import com.plyg.airchat.core.Group
import com.plyg.airchat.core.GroupMember
import com.plyg.airchat.core.GroupMessage
import com.plyg.airchat.core.MemberProposal
import com.plyg.airchat.core.Membership
import com.plyg.airchat.core.Message
import com.plyg.airchat.core.PathClass
import com.plyg.airchat.core.Permissions
import com.plyg.airchat.core.WalkieChannel
import com.plyg.airchat.core.maxFileSize
import com.plyg.airchat.core.groupFile
import com.plyg.airchat.core.inviteBeaconToken
import com.plyg.airchat.core.pairingBeaconLabel
import com.plyg.airchat.net.ConnectionHub
import com.plyg.airchat.net.NetEvent
import com.plyg.airchat.net.Peer
import com.plyg.airchat.net.TransportKind
import com.plyg.airchat.runtime.AirProvider
import com.plyg.airchat.runtime.CallUi
import com.plyg.airchat.runtime.TalkRefusal
import com.plyg.airchat.runtime.TalkUi
import com.plyg.airchat.security.KeyLostException
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlinx.coroutines.flow.drop
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.withTimeoutOrNull
import java.io.IOException
import javax.crypto.Cipher

/** The main screen's tabs. */
enum class HomeTab { CHATS, WALKIE, SETTINGS }

sealed interface Screen {
    data object Loading : Screen
    data object Onboarding : Screen
    data object Locked : Screen
    data object OfferBiometric : Screen
    data class Home(val displayName: String, val airchatId: String) : Screen
    data object AddNearby : Screen
    data object Chat : Screen
    data object GroupChat : Screen
}

/** Walkie-talkie channels (rust/airchat-protocol/docs/protocol.md §11). */
data class WalkieUi(
    val channels: List<WalkieChannel> = emptyList(),
    /** Members of the tuned channel linked now. */
    val peers: List<ChannelPeer> = emptyList(),
    /** A channel's QR code on show, with its name. */
    val sharing: Pair<String, String>? = null,
    /** A key is being derived from a password (about a second). */
    val deriving: Boolean = false,
) {
    val tuned: WalkieChannel? get() = channels.find { it.tuned }
}

data class ChatUi(
    val contactId: Long,
    val name: String,
    val airchatId: String,
    val state: ContactState,
    val permissions: Permissions,
    val messages: List<Message> = emptyList(),
    /** Files being encrypted into the store before they are offered. */
    val preparing: Int = 0,
    /** Until when (Unix ms) the contact is muted. */
    val mutedUntil: Long = 0,
    /** The contact's build was attested as the official one on a verified phone. */
    val verifiedBuild: Boolean = false,
)

data class GroupChatUi(
    val group: Group,
    val members: List<GroupMember> = emptyList(),
    val messages: List<GroupMessage> = emptyList(),
    /** Files being encrypted into the store before they are shared. */
    val preparing: Int = 0,
)

/** A file stored on this device: a 1:1 message's (by its id) or a group message's (by `groupFile`). */
data class StoredFile(val id: Long, val attachment: Attachment)

/** A stored file open in an in-app viewer (requirement S-10). Its content lives in memory only. */
sealed interface Viewer {
    val file: StoredFile

    data class Image(override val file: StoredFile, val bitmap: ImageBitmap) : Viewer
    data class Text(override val file: StoredFile, val text: String) : Viewer
    /** Closed by the view model when the viewer goes away. */
    data class Pdf(override val file: StoredFile, val document: Files.PdfDocument) : Viewer
    /** Played straight from the encrypted store. */
    data class Media(override val file: StoredFile, val source: MediaDataSource, val video: Boolean) : Viewer
    /** No in-app viewer for this type: it can only be saved. */
    data class Other(override val file: StoredFile) : Viewer
}

/**
 * A device in "Add nearby" mode, shown by its beacon label. [peers] are its announcements on each
 * transport that hears it, preferred first.
 */
data class NearbyDevice(val key: String, val label: String, val peers: List<Peer>) {
    val via: List<TransportKind> get() = peers.map { it.kind }.distinct()
}

/** A contact's proposal to add someone to your conversation (requirement M-3). */
data class ProposalUi(val contactId: Long, val contactName: String, val proposal: MemberProposal)

data class SasPrompt(val connection: Long, val emoji: List<String>, val confirmed: Boolean = false)

data class PairingUi(
    /** The label this device announces; the other user picks it from their list. */
    val ownLabel: String? = null,
    val devices: List<NearbyDevice> = emptyList(),
    val connecting: Boolean = false,
    /** The connection of the pairing this device started, once it is open. */
    val attempt: Long? = null,
    val sas: SasPrompt? = null,
    val pairedWith: String? = null,
    @param:StringRes val failure: Int? = null,
    /** This device's QR invite on show (rust/airchat-protocol/docs/protocol.md §4.4). */
    val invite: String? = null,
)

data class UiState(
    val screen: Screen = Screen.Loading,
    val busy: Boolean = false,
    @param:StringRes val error: Int? = null,
    val lockoutSeconds: Long = 0,
    val biometricAvailable: Boolean = false,
    val biometricEnabled: Boolean = false,
    val contacts: List<Contact> = emptyList(),
    val groups: List<Group> = emptyList(),
    val pairing: PairingUi = PairingUi(),
    /** Contacts with an encrypted link up right now, and what carries it. */
    val linked: Map<Long, TransportKind> = emptyMap(),
    /** Contacts linked over Bluetooth only, with messages waiting for Wi-Fi. */
    val waitingForWifi: Set<Long> = emptySet(),
    val chat: ChatUi? = null,
    val groupChat: GroupChatUi? = null,
    val viewer: Viewer? = null,
    /** A short confirmation, e.g. that a file was saved. */
    @param:StringRes val notice: Int? = null,
    /** The groups shared with the open chat's contact while the emergency exit is being confirmed. */
    val emergencyGroups: List<Group>? = null,
    /** What the emergency exit just did. */
    val emergencyResult: EmergencyExit? = null,
    /** Android 17+: whether the user allowed local network access. */
    val networkAllowed: Boolean = true,
    val bluetoothAllowed: Boolean = true,
    val bluetoothOn: Boolean = true,
    /** Links carrying mesh traffic: other AirChat devices around, over Wi-Fi. */
    val meshNeighbours: Int = 0,
    /** Air Providers among them: contacts out of reach can be called through them. */
    val providers: Int = 0,
    /** What this device carries for others as an Air Provider. */
    val airProvider: AirProvider.Status = AirProvider.Status(),
    /** Wi-Fi Aware and on-demand hotspots. */
    val wifiAllowed: Boolean = true,
    /** Debug builds: transports switched off for testing. */
    val disabledTransports: Set<TransportKind> = emptySet(),
    /** Debug builds: whether contacts link directly (off to test paths through Air Providers). */
    val directContactLinks: Boolean = true,
    val receiveWhileLocked: Boolean = true,
    /** Whether people who typed this device's AirChat ID may ask to be added (requirement C-4). */
    val acceptRequests: Boolean = true,
    /** AirChat IDs typed whose owners have not added this device yet (rust/airchat-protocol/docs/protocol.md §4.8). */
    val sentRequests: List<String> = emptyList(),
    /** People who asked to be added, not answered yet. */
    val contactRequests: List<ContactRequest> = emptyList(),
    /** Why the ID typed could not be asked for. */
    @param:StringRes val requestError: Int? = null,
    /** A contact's proposal of a group of the two of you and someone else, waiting for an answer. */
    val memberProposal: ProposalUi? = null,
    /** A call ringing, under way, or just ended; shown over everything, also the lock screen. */
    val call: CallUi? = null,
    /** Push-to-talk with a contact: this device talking, or hearing them. */
    val talk: TalkUi? = null,
    /** This device's last talk was cut short by the contact. */
    val talkRefused: TalkRefusal? = null,
    /** "Answer" was tapped on the notification; answered once the microphone may be used. */
    val answerPending: Boolean = false,
    /** Names of the members of the group whose call or talk is on, by row (contacts or not). */
    val voiceNames: Map<Long, String> = emptyMap(),
    val walkie: WalkieUi = WalkieUi(),
    /** The main screen's tab on show. */
    val homeTab: HomeTab = HomeTab.CHATS,
    /** Each conversation's latest message and unread count, for the chat list. */
    val previews: List<ChatPreview> = emptyList(),
)

/**
 * The UI's view of the [AirChatRuntime][com.plyg.airchat.runtime.AirChatRuntime], which owns the
 * account and the network and outlives this view model.
 */
class AppViewModel(application: Application) : AndroidViewModel(application) {
    private val store = AccountStore(application)
    private val runtime = (application as AirChatApplication).runtime
    private val biometricManager = BiometricManager.from(application)

    var state by mutableStateOf(UiState())
        private set

    /** The account while it is unlocked; never touch a locked one except to unlock it. */
    private val account: Account? get() = runtime.account?.takeUnless { runtime.locked.value }
    private val hub get() = runtime.hub
    private val voice get() = runtime.voice
    private var lockoutTicker: Job? = null
    private var peersJob: Job? = null
    private var previewsJob: Job? = null

    init {
        viewModelScope.launch {
            val exists = withContext(Dispatchers.IO) { store.exists() }
            when {
                account != null -> showHome()
                exists -> showLocked()
                else -> update { copy(screen = Screen.Onboarding) }
            }
        }
        viewModelScope.launch { runtime.locked.drop(1).collect { locked -> if (locked) onLocked() } }
        viewModelScope.launch {
            runtime.linked.collect {
                update { copy(linked = it) }
                startCallOnceOverWifi(it)
            }
        }
        viewModelScope.launch { runtime.waitingForWifi.collect { update { copy(waitingForWifi = it) } } }
        viewModelScope.launch { runtime.bluetoothOn.collect { update { copy(bluetoothOn = it) } } }
        viewModelScope.launch { runtime.meshNeighbours.collect { update { copy(meshNeighbours = it) } } }
        viewModelScope.launch { runtime.providers.collect { update { copy(providers = it) } } }
        viewModelScope.launch { runtime.airProvider.status.collect { update { copy(airProvider = it) } } }
        viewModelScope.launch {
            voice.call.collect {
                update { copy(call = it) }
                it?.groupId?.let { group -> loadVoiceNames(group) }
            }
        }
        viewModelScope.launch {
            voice.talk.collect {
                update { copy(talk = it) }
                it?.groupId?.let { group -> loadVoiceNames(group) }
            }
        }
        viewModelScope.launch { voice.talkRefused.collect { update { copy(talkRefused = it) } } }
        viewModelScope.launch { voice.voiceMessages.collect(::sendVoiceMessage) }
        viewModelScope.launch { runtime.events.collect(::onNetEvent) }
    }

    fun createAccount(displayName: String, pin: CharSequence, confirmation: CharSequence) {
        if (pin.toString() != confirmation.toString()) return update { copy(error = R.string.error_pin_mismatch) }
        runBusy(pin) { pinBytes ->
            val created = store.create(pinBytes, displayName)
            withContext(Dispatchers.Main) { runtime.start(created) }
            if (biometricAvailable()) update { copy(screen = Screen.OfferBiometric, busy = false) } else showHome()
        }
    }

    /** Unlocks the account the runtime keeps locked, or opens it afresh if nothing is running. */
    fun unlockWithPin(pin: CharSequence) = runBusy(pin) { pinBytes ->
        val sealed = runtime.account
        if (sealed != null) {
            store.unsealWithPin(sealed, pinBytes)
            withContext(Dispatchers.Main) { runtime.unsealed() }
        } else {
            val opened = store.unlockWithPin(pinBytes)
            withContext(Dispatchers.Main) { runtime.start(opened) }
        }
        showHome()
    }

    // Biometrics: the activity runs BiometricPrompt with these ciphers and hands them back authenticated.

    fun biometricUnlockCipher(): Cipher? = store.biometricUnlockCipher().also {
        if (it == null) update { copy(biometricEnabled = false) }
    }

    fun unlockWithBiometric(cipher: Cipher) = runBusy { _ ->
        val sealed = runtime.account
        if (sealed != null) {
            store.unsealWithBiometric(sealed, cipher)
            withContext(Dispatchers.Main) { runtime.unsealed() }
        } else {
            val opened = store.unlockWithBiometric(cipher)
            withContext(Dispatchers.Main) { runtime.start(opened) }
        }
        showHome()
    }

    fun biometricEnrollCipher(): Cipher = store.biometricEnrollCipher()

    fun enableBiometric(cipher: Cipher) = runBusy { _ ->
        store.enableBiometric(checkNotNull(account), cipher)
        showHome()
    }

    fun disableBiometric() = runBusy { _ ->
        store.disableBiometric()
        update { copy(busy = false, biometricEnabled = false) }
    }

    fun skipBiometric() = showHome()

    /** Forgotten PIN: wipe everything and start over. */
    fun reset() = runBusy { _ ->
        withContext(Dispatchers.Main) { runtime.stop() }
        store.reset()
        update { copy(screen = Screen.Onboarding, busy = false, biometricEnabled = false, lockoutSeconds = 0) }
    }

    // Locking.

    fun lock() = runtime.lock()

    /** The runtime locked the account (here or after the auto-lock timeout): drop all content. */
    private fun onLocked() {
        stopVoice()
        peersJob?.cancel()
        runtime.visibleChat = null
        runtime.visibleGroup = null
        exporting = null
        showViewer(null)
        update {
            copy(
                contacts = emptyList(),
                groups = emptyList(),
                pairing = PairingUi(),
                chat = null,
                groupChat = null,
                voiceNames = emptyMap(),
                walkie = WalkieUi(),
            )
        }
        showLocked()
    }

    fun setReceiveWhileLocked(enabled: Boolean) {
        runtime.receiveWhileLocked = enabled
        update { copy(receiveWhileLocked = enabled) }
    }

    // Adding by AirChat ID (rust/airchat-protocol/docs/protocol.md §4.8).

    fun setAcceptRequests(enabled: Boolean) {
        runtime.acceptRequests = enabled
        update { copy(acceptRequests = enabled) }
    }

    /** Asks the owner of a typed ID to add this device, whenever the two meet. */
    fun requestContact(id: String) {
        val account = account ?: return
        viewModelScope.launch {
            val error = withContext(Dispatchers.Default) {
                try {
                    account.requestContact(id)
                    null
                } catch (e: CoreException) {
                    when (e) {
                        is CoreException.InvalidId -> R.string.request_invalid_id
                        is CoreException.OwnId -> R.string.request_own_id
                        is CoreException.AlreadyContact -> R.string.request_already_contact
                        is CoreException.Locked -> null
                        else -> R.string.error_unexpected
                    }
                }
            }
            update { copy(requestError = error) }
            if (error == null) runtime.requestsChanged()
            refreshRequests()
        }
    }

    fun dismissRequestError() = update { copy(requestError = null) }

    fun cancelRequest(id: String) {
        val account = account ?: return
        viewModelScope.launch {
            whileUnlocked { account.cancelContactRequest(id) }
            runtime.requestsChanged()
            refreshRequests()
        }
    }

    fun approveRequest(request: ContactRequest) = answerRequest { account, hub ->
        hub.perform { account.approveContactRequest(request.identity) }
    }

    fun declineRequest(request: ContactRequest) = answerRequest { account, hub ->
        hub.perform { account.declineContactRequest(request.identity) }
    }

    private fun answerRequest(answer: (Account, ConnectionHub) -> Unit) {
        val (account, hub) = (account ?: return) to (hub ?: return)
        viewModelScope.launch {
            whileUnlocked { answer(account, hub) }
            refreshRequests()
            refreshContacts()
        }
    }

    private suspend fun refreshRequests() {
        val account = account ?: return
        val sent = whileUnlocked { account.sentRequests() } ?: return
        val received = whileUnlocked { account.contactRequests() } ?: return
        update { copy(sentRequests = sent, contactRequests = received) }
    }

    /** Air Provider mode (requirements AP-1, AP-5); the screen warns about the battery first. */
    fun setAirProvider(enabled: Boolean) = runtime.airProvider.setEnabled(enabled)

    // Permissions.

    /**
     * Asked once, after the first unlock: notifications and what the transports need. Afterwards the
     * transports' permissions are asked again only when the user wants to find someone.
     */
    fun permissionsToAskOnce(): List<String> {
        if (runtime.askedForPermissions) return emptyList()
        val notifications = if (Build.VERSION.SDK_INT >= 33) {
            Manifest.permission.POST_NOTIFICATIONS.takeIf {
                ContextCompat.checkSelfPermission(getApplication(), it) != PackageManager.PERMISSION_GRANTED
            }
        } else {
            null
        }
        return listOfNotNull(notifications) + runtime.missingTransportPermissions()
    }

    fun missingTransportPermissions(): List<String> = runtime.missingTransportPermissions()

    /** After any permission request: start what may run now. */
    fun onPermissionsResult() {
        runtime.askedForPermissions = true
        runtime.startNetwork()
        updateRadios()
    }

    private fun updateRadios() = update {
        copy(
            networkAllowed = runtime.networkPermitted(),
            bluetoothAllowed = runtime.bluetoothPermitted(),
            wifiAllowed = runtime.wifiPermitted(),
            disabledTransports = TransportKind.entries.filterNot(runtime::transportEnabled).toSet(),
            directContactLinks = runtime.directContactLinks,
        )
    }

    /** Debug builds only. */
    fun setTransportEnabled(kind: TransportKind, enabled: Boolean) {
        runtime.setTransportEnabled(kind, enabled)
        updateRadios()
    }

    /** Debug builds only. */
    fun setDirectContactLinks(enabled: Boolean) {
        runtime.setDirectContactLinks(enabled)
        updateRadios()
    }

    // Contacts.

    /** Deletes a contact's keys, and the conversation unless [keepHistory] (requirement C-6). */
    fun deleteContact(id: Long, keepHistory: Boolean) = changeContact(closeChat = !keepHistory) { account ->
        performActions { account.deleteContact(id, keepHistory) }
    }

    /** Blocks a contact (requirement C-7): they can no longer reach this device and are not told. */
    fun blockContact(id: Long) = changeContact { account -> performActions { account.blockContact(id) } }

    fun unblockContact(id: Long) = changeContact { account -> account.unblockContact(id) }

    /** What a contact may do (requirement C-5). */
    fun setPermissions(id: Long, permissions: Permissions) = changeContact { account ->
        account.setPermissions(id, permissions)
    }

    /** Mutes a contact until [untilMs] (Unix ms), or unmutes it with 0. */
    fun muteContact(id: Long, untilMs: Long) = changeContact { account -> account.muteContact(id, untilMs) }

    /** Mutes the open group until [untilMs], or unmutes it with 0. */
    fun muteGroup(untilMs: Long) {
        val account = account ?: return
        val group = state.groupChat?.group ?: return
        viewModelScope.launch {
            groupCall { account.muteGroup(group.id, untilMs) } ?: return@launch
            refreshGroups()
            reloadGroupChat(group.copy(mutedUntil = untilMs))
        }
    }

    fun muteChannel(channel: WalkieChannel, untilMs: Long) = changeChannels { account ->
        account.muteChannel(channel.id, untilMs)
        null
    }

    private fun changeContact(closeChat: Boolean = false, change: (Account) -> Unit) {
        val account = account ?: return
        viewModelScope.launch {
            try {
                whileUnlocked { change(account) } ?: return@launch
            } catch (e: CoreException) {
                if (BuildConfig.DEBUG) Log.w(TAG, "contact change failed", e)
                return@launch update { copy(error = R.string.error_unexpected) }
            }
            if (closeChat) closeChat()
            refreshContacts()
            runtime.contactsChanged()
        }
    }

    // Emergency exit (docs/threat-model.md, A5).

    /** Asks to confirm the emergency exit from the open chat's contact, with the groups it touches. */
    fun askEmergencyExit() {
        val account = account ?: return
        val contactId = state.chat?.contactId ?: return
        viewModelScope.launch {
            val groups = try {
                whileUnlocked { account.groupsSharedWith(contactId) }
            } catch (e: CoreException) {
                if (BuildConfig.DEBUG) Log.w(TAG, "shared groups unavailable", e)
                null
            } ?: return@launch
            update { copy(emergencyGroups = groups) }
        }
    }

    fun dismissEmergencyExit() = update { copy(emergencyGroups = null, emergencyResult = null) }

    /** Cuts the open chat's contact off: blocked, the conversation deleted here, groups changed. */
    fun emergencyExit(leaveGroups: Boolean) {
        val account = account ?: return
        val contactId = state.chat?.contactId ?: return
        update { copy(emergencyGroups = null) }
        viewModelScope.launch {
            val exit = try {
                whileUnlocked { performFor { account.emergencyExit(contactId, leaveGroups).let { it to it.actions } } }
            } catch (e: CoreException) {
                if (BuildConfig.DEBUG) Log.w(TAG, "emergency exit failed", e)
                null
            } ?: return@launch update { copy(error = R.string.error_unexpected) }
            refreshContacts()
            refreshGroups()
            runtime.contactsChanged()
            update { copy(chat = chat?.takeIf { it.contactId == contactId }?.copy(messages = emptyList()), emergencyResult = exit) }
        }
    }

    // Chat.

    fun openChat(contact: Contact) {
        val account = account ?: return
        viewModelScope.launch {
            val messages = whileUnlocked { account.messages(contact.id) } ?: return@launch
            runtime.visibleChat = contact.id
            whileUnlocked { account.markContactRead(contact.id) }
            schedulePreviews()
            update {
                copy(
                    screen = Screen.Chat,
                    chat = ChatUi(
                        contact.id,
                        contact.displayName,
                        contact.airchatId,
                        contact.state,
                        contact.permissions,
                        messages,
                        mutedUntil = contact.mutedUntil,
                        verifiedBuild = contact.verifiedBuild,
                    ),
                )
            }
        }
    }

    /**
     * Moves the open conversation's link from Bluetooth to Wi-Fi, which carries messages, calls and
     * files (rust/airchat-protocol/docs/protocol.md §7.3): this device joins a hotspot the contact opens, once the user
     * accepts Android's connection request.
     */
    fun moveToWifi() {
        val chat = state.chat ?: return
        moveToWifi(chat.contactId, forMessages = true)
    }

    private fun moveToWifi(contactId: Long, forMessages: Boolean = false): Boolean {
        val asked = runtime.requestFastLink(contactId, forMessages = forMessages)
        showNotice(if (asked) R.string.wifi_requested else R.string.wifi_unavailable)
        return asked
    }

    fun closeChat() {
        stopVoice()
        runtime.visibleChat = null
        showViewer(null)
        update { copy(chat = null) }
        showHome()
    }

    fun sendMessage(text: String) {
        val account = account ?: return
        val chat = state.chat ?: return
        val body = text.trim()
        if (body.isEmpty()) return
        val hub = hub
        viewModelScope.launch {
            val message = try {
                whileUnlocked {
                    if (hub != null) {
                        hub.performFor { account.sendMessage(chat.contactId, body).let { it.message to it.actions } }
                    } else {
                        account.sendMessage(chat.contactId, body).message
                    }
                }
            } catch (_: CoreException.InvalidMessage) {
                return@launch update { copy(error = R.string.error_message_too_long) }
            } ?: return@launch
            updateChat(message)
        }
    }

    // Groups.

    /** Creates a group of this device (its admin) and [contactIds]. */
    fun createGroup(name: String, contactIds: List<Long>) {
        val account = account ?: return
        viewModelScope.launch {
            val group = groupCall { performFor { account.createGroup(name.trim(), contactIds).let { it.group to it.actions } } }
                ?: return@launch
            refreshGroups()
            openGroup(group)
        }
    }

    fun openGroup(group: Group) {
        val account = account ?: return
        viewModelScope.launch {
            val (members, messages) = whileUnlocked { account.groupMembers(group.id) to account.groupMessages(group.id) }
                ?: return@launch
            runtime.visibleGroup = group.id
            whileUnlocked { account.markGroupRead(group.id) }
            schedulePreviews()
            update { copy(screen = Screen.GroupChat, error = null, groupChat = GroupChatUi(group, members, messages)) }
        }
    }

    fun closeGroup() {
        stopVoice()
        runtime.visibleGroup = null
        update { copy(groupChat = null) }
        showHome()
    }

    fun sendGroupMessage(text: String) {
        val account = account ?: return
        val group = state.groupChat?.group ?: return
        val body = text.trim()
        if (body.isEmpty()) return
        viewModelScope.launch {
            val message = groupCall {
                performFor { account.sendGroupMessage(group.id, body).let { it.message to it.actions } }
            } ?: return@launch
            updateGroupChat(message)
        }
    }

    /** Encrypts a file the user picked into the store and shares it with the open group. */
    fun sendGroupFile(uri: Uri) {
        val account = account ?: return
        val group = state.groupChat?.group ?: return
        val context = getApplication<Application>()
        updateGroupPreparing(group.id, +1)
        update { copy(error = null) }
        viewModelScope.launch {
            val message = try {
                withContext(Dispatchers.IO) {
                    importFile(
                        account,
                        context,
                        uri,
                        begin = { picked, thumbnail -> account.beginGroupFile(group.id, picked.name, picked.mime, thumbnail) },
                        finish = { file -> performFor { account.finishGroupFile(file).let { it.message to it.actions } } },
                    )
                }
            } catch (e: Exception) {
                when (e) {
                    is CancellationException -> throw e
                    is CoreException.Locked -> Unit
                    is CoreException.InvalidFile -> update { copy(error = R.string.error_file_invalid) }
                    is CoreException.NoSuchGroup -> update { copy(error = R.string.group_gone) }
                    else -> {
                        if (BuildConfig.DEBUG) Log.w(TAG, "could not import a group file", e)
                        update { copy(error = R.string.error_file_unreadable) }
                    }
                }
                null
            } finally {
                updateGroupPreparing(group.id, -1)
            }
            message?.let(::updateGroupChat)
        }
    }

    private fun updateGroupPreparing(groupId: Long, change: Int) = update {
        val chat = groupChat?.takeIf { it.group.id == groupId } ?: return@update this
        copy(groupChat = chat.copy(preparing = (chat.preparing + change).coerceAtLeast(0)))
    }

    /** Starts or retries fetching a group file from the members. */
    fun downloadGroupFile(message: GroupMessage) {
        val account = account ?: return
        viewModelScope.launch {
            try {
                withContext(Dispatchers.Default) {
                    val hub = hub
                    if (hub != null) {
                        hub.perform { account.downloadGroupFile(message.id) }
                    } else {
                        account.downloadGroupFile(message.id)
                            .filterIsInstance<Action.GroupMessageUpdated>()
                            .forEach { updateGroupChat(it.message) }
                    }
                }
            } catch (e: CoreException) {
                if (BuildConfig.DEBUG) Log.w(TAG, "download of a group file refused", e)
                if (e !is CoreException.Locked) update { copy(error = R.string.error_unexpected) }
            }
        }
    }

    /** Adds contacts to the open group; [expiresSecs] (Unix seconds, 0 for never) makes them temporary. */
    fun addGroupMembers(contactIds: List<Long>, expiresSecs: Long) = changeGroup { account, group ->
        account.addGroupMembers(group, contactIds, expiresSecs.toULong()).let { it.group to it.actions }
    }

    fun removeGroupMember(member: GroupMember) = changeGroup { account, group ->
        account.removeGroupMember(group, member.identity).let { it.group to it.actions }
    }

    /** The user's display name, as contacts see it. */
    fun displayName(): String = (state.screen as? Screen.Home)?.displayName ?: account?.displayName().orEmpty()

    /** Proposes a group of this device, the open conversation's contact and another contact. */
    fun proposeMember(personId: Long, groupName: String, expiresSecs: Long) {
        val (account, hub) = (account ?: return) to (hub ?: return)
        val with = state.chat?.contactId ?: return
        viewModelScope.launch {
            val error = withContext(Dispatchers.Default) {
                try {
                    hub.perform { account.proposeMember(with, personId, groupName, expiresSecs.toULong()) }
                    null
                } catch (e: CoreException) {
                    when (e) {
                        is CoreException.NotLinked -> R.string.propose_member_not_linked
                        is CoreException.InvalidGroup -> R.string.group_invalid
                        is CoreException.Locked -> null
                        else -> R.string.error_unexpected
                    }
                }
            }
            update { if (error != null) copy(error = error) else copy(notice = R.string.propose_member_sent) }
        }
    }

    /** The user answers a contact's proposal; on yes the contact makes the group. */
    fun answerMemberProposal(agree: Boolean) {
        val (account, hub) = (account ?: return) to (hub ?: return)
        val asked = state.memberProposal ?: return
        update { copy(memberProposal = null) }
        viewModelScope.launch {
            withContext(Dispatchers.Default) {
                try {
                    hub.perform { account.answerMemberProposal(asked.contactId, asked.proposal.id, agree) }
                } catch (e: CoreException) {
                    if (BuildConfig.DEBUG) Log.w(TAG, "could not answer a proposal", e)
                }
            }
        }
    }

    fun addGroupMembersForCall(contactIds: List<Long>) = changeGroup { account, group ->
        account.addGroupMembersForCall(group, contactIds).let { it.group to it.actions }
    }

    /** From the call screen: adds contacts to the group whose call this is. */
    fun addToCallGroup(contactIds: List<Long>, expiresSecs: Long, forCall: Boolean) {
        val groupId = state.call?.groupId ?: return
        changeGroup(groupId) { account, group ->
            val change = if (forCall) {
                account.addGroupMembersForCall(group, contactIds)
            } else {
                account.addGroupMembers(group, contactIds, expiresSecs.toULong())
            }
            change.group to change.actions
        }
    }

    fun setGroupAdmin(member: GroupMember, admin: Boolean) = changeGroup { account, group ->
        account.setGroupAdmin(group, member.identity, admin).let { it.group to it.actions }
    }

    fun leaveGroup() = changeGroup { account, group -> account.leaveGroup(group).let { it.group to it.actions } }

    /** Deletes the open group for every member (an admin only); the chat closes. */
    fun deleteGroupForEveryone() = changeGroup { account, group ->
        account.deleteGroupForEveryone(group).let { it.group to it.actions }
    }

    /** Deletes the open group's conversation, which this device left or was removed from. */
    fun deleteGroupChat() {
        val account = account ?: return
        val group = state.groupChat?.group?.id ?: return
        viewModelScope.launch {
            groupCall { performFor { Unit to account.deleteGroup(group) } } ?: return@launch
            closeGroup()
            refreshGroups()
        }
    }

    private fun changeGroup(
        groupId: Long? = state.groupChat?.group?.id,
        change: (Account, Long) -> Pair<Group, List<Action>>,
    ) {
        val account = account ?: return
        val group = groupId ?: return
        viewModelScope.launch {
            val changed = groupCall { performFor { change(account, group) } } ?: return@launch
            refreshGroups()
            reloadGroupChat(changed)
            if (state.call?.groupId == group) loadVoiceNames(group)
        }
    }

    /** Runs a group call off the main thread; null after showing why it failed, or when locked. */
    private suspend fun <T> groupCall(call: () -> T?): T? = try {
        update { copy(error = null) }
        whileUnlocked(call)
    } catch (e: CoreException) {
        if (BuildConfig.DEBUG) Log.w(TAG, "group call failed", e)
        update {
            copy(
                error = when (e) {
                    is CoreException.InvalidGroup -> R.string.group_invalid
                    is CoreException.NotGroupAdmin -> R.string.group_not_admin
                    is CoreException.NoSuchGroup -> R.string.group_gone
                    is CoreException.InvalidMessage -> R.string.error_message_too_long
                    is CoreException.NotInCall -> R.string.group_not_in_call
                    else -> R.string.error_unexpected
                },
            )
        }
        null
    }

    /** Runs a core call through the hub, which carries out its actions; without one, just the call. */
    private fun <T> performFor(call: () -> Pair<T, List<Action>>): T? {
        val hub = hub
        return if (hub != null) hub.performFor(call) else call().first
    }

    /** Shows the open group anew: its members may have changed. */
    private suspend fun reloadGroupChat(group: Group) {
        val account = account ?: return
        if (state.groupChat?.group?.id != group.id) return
        // Deleted for everyone, here or by an admin: nothing is left to show.
        if (group.membership == Membership.DELETED) return closeGroup()
        val members = whileUnlocked { account.groupMembers(group.id) } ?: return
        update {
            val open = groupChat?.takeIf { it.group.id == group.id } ?: return@update this
            copy(groupChat = open.copy(group = group, members = members))
        }
    }

    /** Adds or replaces a message in the open group, if it belongs there. */
    private fun updateGroupChat(message: GroupMessage) {
        schedulePreviews()
        val chat = state.groupChat?.takeIf { it.group.id == message.groupId } ?: return
        val messages = chat.messages.filterNot { it.id == message.id } + message
        update { copy(groupChat = chat.copy(messages = messages.sortedWith(compareBy({ it.storedAtMs }, { it.id })))) }
    }

    private suspend fun refreshGroups() {
        val account = account ?: return
        val groups = whileUnlocked { account.groups() } ?: return
        update { copy(groups = groups) }
        schedulePreviews()
    }

    // Walkie-talkie channels.

    /** The walkie-talkie: a tab of the main screen. */
    fun openWalkie() {
        if (state.screen !is Screen.Home) showHome()
        update { copy(homeTab = HomeTab.WALKIE, error = null) }
        viewModelScope.launch { refreshWalkie() }
    }

    fun closeWalkie() {
        update { copy(walkie = walkie.copy(sharing = null), homeTab = HomeTab.CHATS) }
    }

    fun selectTab(tab: HomeTab) {
        if (tab == HomeTab.WALKIE) return openWalkie()
        update { copy(homeTab = tab, error = null, walkie = walkie.copy(sharing = null)) }
    }

    /** The chat list again soon: what changed may come in several events at once. */
    private fun schedulePreviews() {
        previewsJob?.cancel()
        previewsJob = viewModelScope.launch {
            delay(PREVIEWS_DELAY_MS)
            refreshPreviews()
        }
    }

    /** Reloads the chat list; a conversation open counts as read up to its latest message. */
    private suspend fun refreshPreviews() {
        val account = account ?: return
        val previews = whileUnlocked {
            state.chat?.let { account.markContactRead(it.contactId) }
            state.groupChat?.let { account.markGroupRead(it.group.id) }
            account.chatPreviews()
        } ?: return
        update { copy(previews = previews) }
    }

    /** A new channel with a random key, tuned in at once and its code shown to let others in. */
    fun createChannel(name: String) = changeChannels { account ->
        val channel = account.createChannel(name.trim())
        tune(account, channel.id)
        account.channelQr(channel.id) to channel.name
    }

    fun joinChannelByQr(text: String) = changeChannels { account ->
        val channel = account.addChannelFromQr(text)
        tune(account, channel.id)
        null
    }

    /** The password is turned into bytes here and wiped afterwards. */
    fun joinChannelByPassword(name: String, password: CharSequence) {
        val bytes = password.toString().encodeToByteArray()
        update { copy(walkie = walkie.copy(deriving = true)) }
        changeChannels(after = { update { copy(walkie = walkie.copy(deriving = false)) } }) { account ->
            try {
                val channel = account.addChannelFromPassword(name.trim(), bytes)
                tune(account, channel.id)
            } finally {
                bytes.fill(0)
            }
            null
        }
    }

    /** Tunes in to a channel, or out of all with `null`. */
    fun tuneChannel(channelId: Long?) = changeChannels { account ->
        tune(account, channelId)
        null
    }

    fun shareChannel(channel: WalkieChannel) = changeChannels { account -> account.channelQr(channel.id) to channel.name }

    fun dismissShare() = update { copy(walkie = walkie.copy(sharing = null)) }

    fun deleteChannel(channel: WalkieChannel) = changeChannels { account ->
        performActions { account.deleteChannel(channel.id) }
        runtime.channelChanged()
        null
    }

    fun startChannelTalk(): Boolean {
        val channel = state.walkie.tuned ?: return false
        if (state.walkie.peers.isEmpty()) {
            // A member out of reach may be found through Air Providers (§11.5): the next press talks.
            if (runtime.findChannelPath()) showNotice(R.string.talk_via_provider) else update { copy(error = R.string.walkie_nobody_to_talk) }
            return false
        }
        return voice.startChannelTalk(channel.id)
    }

    private fun tune(account: Account, channelId: Long?) {
        performActions { account.tuneChannel(channelId) }
        runtime.channelChanged()
    }

    /** Runs a change of the channel list off the main thread; may return a code to show. */
    private fun changeChannels(after: () -> Unit = {}, change: (Account) -> Pair<String, String>?) {
        val account = account ?: return
        update { copy(error = null) }
        viewModelScope.launch {
            val shown = try {
                whileUnlocked { change(account) }
            } catch (e: CoreException) {
                if (BuildConfig.DEBUG) Log.w(TAG, "channel change failed", e)
                update {
                    copy(
                        error = when (e) {
                            is CoreException.NotAChannel -> R.string.walkie_not_a_channel
                            is CoreException.PasswordTooShort -> R.string.walkie_password_short
                            is CoreException.InvalidChannelName -> R.string.group_invalid
                            else -> R.string.error_unexpected
                        },
                    )
                }
                null
            } finally {
                after()
            }
            refreshWalkie()
            if (shown != null) update { copy(walkie = walkie.copy(sharing = shown)) }
        }
    }

    private suspend fun refreshWalkie() {
        val account = account ?: return
        val (channels, peers) = whileUnlocked { account.channels() to account.channelPeers() } ?: return
        update { copy(walkie = walkie.copy(channels = channels, peers = peers)) }
    }

    // Calls and push-to-talk. The microphone permission is asked by the screen before these.

    fun microphonePermitted() = voice.microphonePermitted()

    fun microphoneDenied() = update { copy(error = R.string.microphone_needed) }

    fun cameraPermitted() =
        ContextCompat.checkSelfPermission(getApplication(), Manifest.permission.CAMERA) == PackageManager.PERMISSION_GRANTED

    fun cameraDenied() = update { copy(error = R.string.camera_needed) }

    /**
     * A call asked for before a link could carry it (over Bluetooth, or none at all): it starts once
     * one can, over Wi-Fi or a path through Air Providers.
     */
    private var callOnceOverWifi: Triple<Long, Boolean, Long>? = null

    /**
     * Calls go over Wi-Fi (§7.3): a contact nearby over Bluetooth gets a hotspot, one out of reach a
     * path through Air Providers (§12); the app picks the way (requirement AP-7).
     */
    fun call(contactId: Long, video: Boolean = false) {
        val via = state.linked[contactId]
        if (via != null && via != TransportKind.BLE && (!video || runtime.carriesVideo(contactId))) {
            if (!voice.startCall(contactId, video)) update { copy(error = R.string.error_unexpected) }
            return
        }
        val now = SystemClock.elapsedRealtime()
        if (via == TransportKind.BLE && runtime.requestFastLink(contactId, forCall = true)) {
            callOnceOverWifi = Triple(contactId, video, now)
            showNotice(R.string.call_needs_wifi)
            return
        }
        // A video call with no provider around that carries video goes as a voice call.
        val pathClass = if (video && runtime.providers(PathClass.VIDEO) > 0) PathClass.VIDEO else PathClass.VOICE
        if (runtime.findPath(contactId, pathClass)) {
            callOnceOverWifi = Triple(contactId, video, now)
            showNotice(R.string.call_via_provider)
            return
        }
        when (via) {
            // Over a path that carries no video, with no better one to be had: a voice call.
            TransportKind.RELAY -> if (!voice.startCall(contactId, false)) update { copy(error = R.string.error_unexpected) }
            TransportKind.BLE -> showNotice(R.string.wifi_unavailable)
            else -> update { copy(error = R.string.contact_unreachable) }
        }
    }

    private fun startCallOnceOverWifi(linked: Map<Long, TransportKind>) {
        val (contactId, video, askedAt) = callOnceOverWifi ?: return
        if (SystemClock.elapsedRealtime() - askedAt > CALL_WAITS_FOR_WIFI_MS) return run { callOnceOverWifi = null }
        val via = linked[contactId] ?: return
        if (via == TransportKind.BLE) return
        callOnceOverWifi = null
        // Over a path that carries no video, the call goes without it (requirement AP-7).
        if (!voice.startCall(contactId, video && runtime.carriesVideo(contactId))) update { copy(error = R.string.error_unexpected) }
    }

    /** No path came for a call waiting for one: without video if that was the trouble, else give up. */
    private fun pathFailed(contactId: Long, pathClass: PathClass) {
        val (waiting, video, askedAt) = callOnceOverWifi?.takeIf { it.first == contactId } ?: return
        if (pathClass == PathClass.FILES) return
        if (pathClass == PathClass.VIDEO) {
            if (state.linked[contactId] == TransportKind.RELAY) return startCallOnceOverWifi(state.linked)
            if (runtime.findPath(waiting, PathClass.VOICE)) return run { callOnceOverWifi = Triple(waiting, video, askedAt) }
        }
        callOnceOverWifi = null
        update { copy(error = R.string.contact_unreachable) }
    }

    // Video in a call; the screen asks for the camera permission first.

    fun setCamera(on: Boolean) = voice.setCamera(on)

    fun switchCamera() = voice.switchCamera()

    /** The contact's picture as it arrives, for the view that shows it. */
    val remoteVideoFormat get() = voice.remoteFormat

    fun setLocalPreview(texture: android.graphics.SurfaceTexture?) = voice.setLocalPreview(texture)

    fun setRemoteView(texture: android.graphics.SurfaceTexture?) = voice.setRemoteView(texture)

    /** Each group call participant's picture as it arrives, by row. */
    val memberVideoFormats get() = voice.memberFormats

    fun setMemberView(member: Long, texture: android.graphics.SurfaceTexture?) = voice.setMemberView(member, texture)

    fun answerCall() {
        update { copy(answerPending = false) }
        voice.answer()
    }

    /** From the notification's "Answer": the screen answers once the microphone is settled. */
    fun answerRequested() = update { copy(answerPending = true) }

    fun hangUp() = voice.hangUp()

    fun setMuted(muted: Boolean) = voice.setMuted(muted)

    fun setSpeaker(speaker: Boolean) = voice.setSpeaker(speaker)

    /** Push-to-talk pressed; false if talking cannot start now. */
    fun startTalk(contactId: Long): Boolean {
        // Push-to-talk goes over Wi-Fi (§7.3) or a path through Air Providers (§12): set it up; the
        // next press talks.
        when (state.linked[contactId]) {
            TransportKind.BLE -> when {
                runtime.requestFastLink(contactId, forMessages = true) -> showNotice(R.string.talk_needs_wifi)
                runtime.findPath(contactId, PathClass.VOICE) -> showNotice(R.string.talk_via_provider)
                else -> showNotice(R.string.wifi_unavailable)
            }
            null -> if (runtime.findPath(contactId, PathClass.VOICE)) {
                showNotice(R.string.talk_via_provider)
            } else {
                update { copy(error = R.string.contact_unreachable) }
            }
            else -> return voice.startTalk(contactId)
        }
        return false
    }

    /** Group push-to-talk; with no member linked, they are looked for through Air Providers (§9.6). */
    fun startGroupTalk(groupId: Long): Boolean {
        if (voice.startGroupTalk(groupId)) return true
        if (runtime.reachGroup(groupId)) showNotice(R.string.talk_via_provider)
        return false
    }

    fun callGroup(groupId: Long) {
        if (!voice.startGroupCall(groupId)) update { copy(error = R.string.group_nobody_nearby) }
    }

    /** Whether the open group's push-to-talk plays at once. */
    fun setGroupPtt(allow: Boolean) {
        val account = account ?: return
        val group = state.groupChat?.group ?: return
        viewModelScope.launch {
            groupCall { account.setGroupPtt(group.id, allow) } ?: return@launch
            refreshGroups()
            reloadGroupChat(group.copy(instantVoice = allow))
        }
    }

    /** Who is in the group of a call or talk, to name them; nothing while locked. */
    private fun loadVoiceNames(groupId: Long) {
        val account = account ?: return
        viewModelScope.launch {
            val members = whileUnlocked {
                try {
                    account.groupMembers(groupId)
                } catch (_: CoreException) {
                    emptyList()
                }
            } ?: return@launch
            update { copy(voiceNames = members.mapNotNull { m -> m.rowId?.let { it to m.name } }.toMap()) }
        }
    }

    fun endTalk() = voice.endTalk()

    fun dismissTalkRefusal() = voice.dismissTalkRefusal()

    // Voice messages (requirement V-3).

    /** A talk the other side did not take live, sent as a voice message to the contact or group. */
    private fun sendVoiceMessage(message: VoiceMessage) {
        val account = account ?: return message.ogg.fill(0)
        val name = "voice-" + LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss")) + ".ogg"
        viewModelScope.launch {
            try {
                val group = message.groupId
                if (group != null) {
                    val sent = withContext(Dispatchers.IO) {
                        val file = account.beginGroupFile(group, name, voiceMime(), null)
                        writeVoice(account, file, message.ogg)
                        performFor { account.finishGroupFile(file).let { it.message to it.actions } }
                    }
                    sent?.let(::updateGroupChat)
                } else {
                    val sent = withContext(Dispatchers.IO) {
                        val file = account.beginFile(message.contactId, name, voiceMime(), null)
                        writeVoice(account, file, message.ogg)
                        performFor { account.finishFile(file).let { it.message to it.actions } }
                    }
                    sent?.let(::updateChat)
                }
            } catch (e: CoreException) {
                if (BuildConfig.DEBUG) Log.w(TAG, "could not send a voice message", e)
                if (e !is CoreException.Locked) update { copy(error = R.string.error_unexpected) }
            } finally {
                message.ogg.fill(0)
            }
        }
    }

    private fun writeVoice(account: Account, file: Long, ogg: ByteArray) {
        try {
            account.writeFile(file, ogg)
        } catch (e: CoreException) {
            runCatching { account.abortFile(file) }
            throw e
        }
    }

    private var player: MediaPlayer? = null
    private var playerJob: Job? = null
    private val _voicePlayback = MutableStateFlow<VoicePlayback?>(null)

    /** The voice message playing in the open conversation, if one is. */
    val voicePlayback: StateFlow<VoicePlayback?> = _voicePlayback

    /**
     * Plays voice message [file] (a group's named by [groupFile]) of [size] bytes, or pauses or
     * resumes it if it is the one playing. Played straight from the encrypted store; the first
     * play of one that came in starts its quarter of an hour.
     */
    fun toggleVoice(file: Long, size: Long) {
        val current = _voicePlayback.value
        val playing = player
        if (current?.file == file && playing != null) {
            if (playing.isPlaying) {
                playing.pause()
                _voicePlayback.value = current.copy(playing = false)
            } else {
                playing.start()
                _voicePlayback.value = current.copy(playing = true)
                followVoice()
            }
            return
        }
        stopVoice()
        val account = account ?: return
        val media = MediaPlayer()
        player = media
        _voicePlayback.value = VoicePlayback(file, playing = false, positionMs = 0, durationMs = 0)
        media.setAudioAttributes(
            AudioAttributes.Builder()
                .setUsage(AudioAttributes.USAGE_MEDIA)
                .setContentType(AudioAttributes.CONTENT_TYPE_SPEECH)
                .build(),
        )
        media.setOnPreparedListener {
            if (player !== it) return@setOnPreparedListener
            it.start()
            _voicePlayback.value = VoicePlayback(file, playing = true, positionMs = 0, durationMs = it.duration.toLong())
            followVoice()
        }
        media.setOnCompletionListener { if (player === it) stopVoice() }
        media.setOnErrorListener { player, _, _ ->
            if (this.player === player) stopVoice()
            true
        }
        try {
            media.setDataSource(Files.StoredSource(account, file, size))
            media.prepareAsync()
        } catch (e: Exception) {
            if (BuildConfig.DEBUG) Log.w(TAG, "could not play a voice message", e)
            stopVoice()
            return
        }
        viewModelScope.launch(Dispatchers.Default) {
            try {
                hub?.perform { account.voicePlayed(file) }
            } catch (_: CoreException) {
            }
        }
    }

    fun stopVoice() {
        playerJob?.cancel()
        playerJob = null
        player?.release()
        player = null
        _voicePlayback.value = null
    }

    /** Keeps the position up to date while it plays. */
    private fun followVoice() {
        playerJob?.cancel()
        playerJob = viewModelScope.launch {
            while (true) {
                val media = player ?: break
                val position = runCatching { media.currentPosition.toLong() }.getOrNull() ?: break
                _voicePlayback.update { it?.copy(positionMs = position) }
                if (!media.isPlaying) break
                delay(VOICE_POSITION_EVERY_MS)
            }
        }
    }

    // Files.

    /** Encrypts a file the user picked into the store and offers it to the open conversation's contact. */
    fun sendFile(uri: Uri) {
        val account = account ?: return
        val contactId = state.chat?.contactId ?: return
        val context = getApplication<Application>()
        updatePreparing(contactId, +1)
        update { copy(error = null) }
        viewModelScope.launch {
            val message = try {
                withContext(Dispatchers.IO) {
                    importFile(
                        account,
                        context,
                        uri,
                        begin = { picked, thumbnail -> account.beginFile(contactId, picked.name, picked.mime, thumbnail) },
                        finish = { file ->
                            val hub = hub
                            if (hub != null) {
                                hub.performFor { account.finishFile(file).let { it.message to it.actions } }
                            } else {
                                account.finishFile(file).message
                            }
                        },
                    )
                }
            } catch (e: Exception) {
                when (e) {
                    is CancellationException -> throw e
                    is CoreException.Locked -> Unit
                    is CoreException.InvalidFile -> update { copy(error = R.string.error_file_invalid) }
                    // Providers fail in many ways (IOException, SecurityException, IllegalArgumentException, …).
                    else -> {
                        if (BuildConfig.DEBUG) Log.w(TAG, "could not import a file", e)
                        update { copy(error = R.string.error_file_unreadable) }
                    }
                }
                null
            } finally {
                updatePreparing(contactId, -1)
            }
            message?.let(::updateChat)
        }
    }

    /** Encrypts a picked file into the store: [begin] names it, [finish] shares it. */
    private fun <T> importFile(
        account: Account,
        context: Application,
        uri: Uri,
        begin: (Files.Picked, ByteArray?) -> Long,
        finish: (Long) -> T?,
    ): T? {
        val resolver = context.contentResolver
        val picked = Files.describe(resolver, uri)
        if ((picked.size ?: 0) > maxFileSize().toLong()) throw CoreException.InvalidFile("too large")
        val thumbnail = Files.thumbnail(context, uri, picked.mime)
        if (BuildConfig.DEBUG) Log.d(TAG, "importing ${picked.mime}, thumbnail ${thumbnail?.size} bytes")
        val file = begin(picked, thumbnail)
        try {
            val input = resolver.openInputStream(uri) ?: throw IOException("the provider gave no stream")
            val buffer = ByteArray(Files.PIECE)
            try {
                input.use {
                    while (true) {
                        val read = input.read(buffer)
                        if (read < 0) break
                        if (read == 0) continue
                        val piece = if (read == buffer.size) buffer else buffer.copyOf(read)
                        account.writeFile(file, piece)
                        if (piece !== buffer) piece.fill(0)
                    }
                }
            } finally {
                buffer.fill(0)
            }
            return finish(file)
        } catch (e: Exception) {
            try {
                account.abortFile(file)
            } catch (_: CoreException) {
            }
            throw e
        }
    }

    private fun updatePreparing(contactId: Long, change: Int) = update {
        val chat = chat?.takeIf { it.contactId == contactId } ?: return@update this
        copy(chat = chat.copy(preparing = (chat.preparing + change).coerceAtLeast(0)))
    }

    /** Starts or retries fetching a file the contact offered. */
    fun downloadFile(message: Message) {
        if (BuildConfig.DEBUG) Log.d(TAG, "download file ${message.id} asked, state ${message.attachment?.state}")
        val account = account ?: return
        viewModelScope.launch {
            try {
                withContext(Dispatchers.Default) { performActions { account.downloadFile(message.id) } }
            } catch (e: CoreException) {
                if (BuildConfig.DEBUG) Log.w(TAG, "download of file ${message.id} refused", e)
                if (e !is CoreException.Locked) update { copy(error = R.string.error_unexpected) }
                return@launch
            }
            if (BuildConfig.DEBUG) Log.d(TAG, "download file ${message.id} started, link ${state.linked[message.contactId]}")
            // Files go over Wi-Fi (§7.3): over Bluetooth, set it up (§8.3).
            if (state.linked[message.contactId] == TransportKind.BLE) {
                runtime.requestFastLink(message.contactId, forDownloads = true)
            }
        }
    }

    /** Opens a stored file in an in-app viewer. */
    fun openFile(message: Message) {
        val attachment = message.attachment?.takeIf { it.state == AttachmentState.COMPLETE } ?: return
        openStored(StoredFile(message.id, attachment))
    }

    fun openGroupFile(message: GroupMessage) {
        val attachment = message.attachment?.takeIf { it.state == AttachmentState.COMPLETE } ?: return
        openStored(StoredFile(groupFile(message.id), attachment))
    }

    private fun openStored(file: StoredFile) {
        val account = account ?: return
        val attachment = file.attachment
        val size = attachment.size.toLong()
        val mime = attachment.mime
        viewModelScope.launch {
            val viewer = withContext(Dispatchers.Default) {
                try {
                    when {
                        mime.startsWith("image/") && size <= Files.MAX_VIEWABLE_IMAGE -> {
                            val bytes = Files.readAll(account, file.id, size)
                            try {
                                Files.decode(bytes, VIEWER_MAX_PX)?.let { Viewer.Image(file, it.asImageBitmap()) }
                            } finally {
                                bytes.fill(0)
                            }
                        }
                        mime.startsWith("video/") || mime.startsWith("audio/") ->
                            Viewer.Media(file, Files.StoredSource(account, file.id, size), mime.startsWith("video/"))
                        mime == "application/pdf" -> Files.openPdf(account, file.id, size)?.let { Viewer.Pdf(file, it) }
                        (mime.startsWith("text/") || mime == "application/json") && size <= Files.MAX_VIEWABLE_TEXT -> {
                            val bytes = Files.readAll(account, file.id, size)
                            try {
                                Viewer.Text(file, bytes.decodeToString())
                            } finally {
                                bytes.fill(0)
                            }
                        }
                        else -> null
                    } ?: Viewer.Other(file)
                } catch (_: CoreException) {
                    null
                } catch (_: IOException) {
                    null
                } catch (_: OutOfMemoryError) {
                    Viewer.Other(file)
                }
            } ?: return@launch update { copy(error = R.string.error_unexpected) }
            showViewer(viewer)
        }
    }

    fun closeViewer() = showViewer(null)

    private fun showViewer(viewer: Viewer?) {
        (state.viewer as? Viewer.Pdf)?.document?.close()
        update { copy(viewer = viewer) }
    }

    override fun onCleared() {
        stopVoice()
        (state.viewer as? Viewer.Pdf)?.document?.close()
    }

    /** The file the user is saving outside AirChat, while they pick where. */
    private var exporting: StoredFile? = null

    /** The user confirmed the warning and now picks where to save [file]. */
    fun beginExport(file: StoredFile) {
        exporting = file
    }

    /** Writes the file being exported to where the user picked, unencrypted (requirement S-10). */
    fun exportTo(uri: Uri?) {
        val file = exporting ?: return
        exporting = null
        if (uri == null) return
        val account = account ?: return
        val size = file.attachment.size.toLong()
        val resolver = getApplication<Application>().contentResolver
        viewModelScope.launch {
            val saved = withContext(Dispatchers.IO) {
                try {
                    // A new document: nothing to truncate, and not every provider supports "wt".
                    val output = resolver.openOutputStream(uri, "w") ?: throw IOException("the provider gave no stream")
                    output.use {
                        var position = 0L
                        while (position < size) {
                            val piece = account.readFile(file.id, position.toULong(), Files.PIECE.toUInt())
                            if (piece.isEmpty()) throw IOException("stored file ends early")
                            output.write(piece)
                            position += piece.size
                            piece.fill(0)
                        }
                    }
                    true
                } catch (e: Exception) {
                    if (e is CancellationException) throw e
                    if (BuildConfig.DEBUG) Log.w(TAG, "could not export a file", e)
                    // Leave no partial copy behind.
                    try {
                        DocumentsContract.deleteDocument(resolver, uri)
                    } catch (_: Exception) {
                    }
                    false
                }
            }
            if (saved) showNotice(R.string.file_saved) else update { copy(error = R.string.error_file_save) }
        }
    }

    private fun showNotice(@StringRes notice: Int) {
        update { copy(notice = notice) }
        viewModelScope.launch {
            delay(NOTICE_MS)
            if (state.notice == notice) update { copy(notice = null) }
        }
    }

    /** Tries a message not delivered within a day again (rust/airchat-protocol/docs/protocol.md §10.5). */
    fun tryMessageAgain(message: Message) {
        val account = account ?: return
        try {
            performActions { account.tryMessageAgain(message.id) }
        } catch (_: CoreException) {
            // Delivered meanwhile after all, or locked: nothing to try.
        }
    }

    /** Tries a group message no member took within a day again (rust/airchat-protocol/docs/protocol.md §9.5). */
    fun tryGroupMessageAgain(message: GroupMessage) {
        val account = account ?: return
        try {
            performActions { account.tryGroupMessageAgain(message.id) }
        } catch (_: CoreException) {
            // A member took it meanwhile after all, or locked: nothing to try.
        }
    }

    /** Runs a core call through the hub, which carries out its actions; without one, shows what changed. */
    private fun performActions(call: () -> List<Action>) {
        val hub = hub
        if (hub != null) {
            hub.perform(call)
        } else {
            call().filterIsInstance<Action.MessageUpdated>().forEach { updateChat(it.message) }
        }
    }

    /** Adds or replaces a message in the open conversation, if it belongs there. */
    private fun updateChat(message: Message) {
        schedulePreviews()
        val chat = state.chat?.takeIf { it.contactId == message.contactId } ?: return
        val messages = chat.messages.filterNot { it.id == message.id } + message
        update { copy(chat = chat.copy(messages = messages.sortedWith(compareBy({ it.storedAtMs }, { it.id })))) }
    }

    /** Reloads the contact list, and the open conversation's contact with it. */
    private suspend fun refreshContacts() {
        val account = account ?: return
        val contacts = whileUnlocked { account.contacts() } ?: return
        update {
            val open = chat?.let { chat -> contacts.find { it.id == chat.contactId } }
            copy(
                contacts = contacts,
                chat = if (open != null) {
                    chat?.copy(
                        state = open.state,
                        permissions = open.permissions,
                        mutedUntil = open.mutedUntil,
                        verifiedBuild = open.verifiedBuild,
                    )
                } else {
                    chat
                },
            )
        }
        schedulePreviews()
    }

    /**
     * Runs a core call off the main thread; null if the account got locked meanwhile (the lock
     * screen is on its way then).
     */
    private suspend fun <T> whileUnlocked(call: () -> T): T? = withContext(Dispatchers.Default) {
        try {
            call()
        } catch (_: CoreException.Locked) {
            null
        }
    }

    // Nearby Pairing.

    fun openAddNearby() {
        val account = account ?: return
        if (!runtime.canDiscover) return updateRadios()
        viewModelScope.launch {
            val beacon = whileUnlocked { account.openPairing() } ?: return@launch
            nearbyToken = beacon.token
            runtime.setPairingToken(beacon.token)
            update { copy(screen = Screen.AddNearby, pairing = PairingUi(ownLabel = beacon.label)) }
            peersJob?.cancel()
            peersJob = launch {
                runtime.peers.collect { peers ->
                    val devices = peers
                        .mapNotNull { peer -> peer.pairingToken?.let { it.toHex() to peer } }
                        .groupBy({ it.first }, { it.second })
                        .mapNotNull { (key, group) ->
                            pairingBeaconLabel(group.first().pairingToken!!)?.let { label ->
                                NearbyDevice(key, label, group.sortedBy { it.kind })
                            }
                        }
                        .sortedBy { it.label }
                    update { copy(pairing = pairing.copy(devices = devices)) }
                }
            }
        }
    }

    /** The token "Add nearby" announces, to go back to when a QR invite is put away. */
    private var nearbyToken: ByteArray? = null

    /** Shows a QR invite and announces its token, so the scanner finds this device. */
    fun showInvite() {
        val account = account ?: return
        viewModelScope.launch {
            val code = whileUnlocked { account.createInvite() } ?: return@launch
            val token = inviteBeaconToken(code) ?: return@launch
            runtime.setPairingToken(token)
            update { copy(pairing = pairing.copy(invite = code)) }
        }
    }

    fun hideInvite() {
        if (state.pairing.invite == null) return
        runtime.setPairingToken(nearbyToken)
        update { copy(pairing = pairing.copy(invite = null)) }
    }

    /** Pairs with the device whose QR invite was scanned: the one announcing its token. */
    fun pairWithCode(code: String) {
        val (account, hub) = (account ?: return) to (hub ?: return)
        val token = inviteBeaconToken(code)
            ?: return update { copy(pairing = pairing.copy(failure = R.string.pairing_not_an_invite)) }
        if (state.pairing.connecting || state.pairing.sas != null) return
        update { copy(pairing = pairing.copy(connecting = true, failure = null)) }
        viewModelScope.launch {
            // The device may need a few seconds to show up after the code was read.
            val peers = withTimeoutOrNull(INVITE_FIND_MS) {
                runtime.peers.first { all -> all.any { it.pairingToken contentEquals token } }
            }.orEmpty().filter { it.pairingToken contentEquals token }.sortedBy { it.kind }
            for (peer in peers) {
                try {
                    withContext(Dispatchers.IO) {
                        val connection = hub.attach(peer.connect(), peer.kind)
                        update { copy(pairing = pairing.copy(attempt = connection)) }
                        hub.perform { account.pairWithInvite(connection.toULong(), code) }
                    }
                    return@launch
                } catch (e: Exception) {
                    if (e !is IOException && e !is SecurityException && e !is CoreException) throw e
                    if (BuildConfig.DEBUG) Log.w(TAG, "could not reach the invite's device over ${peer.kind}", e)
                }
            }
            update { copy(pairing = pairing.copy(connecting = false, failure = R.string.pairing_unreachable)) }
        }
    }

    fun closeAddNearby() {
        // Discovery keeps running: it is also how contacts find each other.
        peersJob?.cancel()
        runtime.setPairingToken(null)
        val (account, hub) = (account ?: return) to (hub ?: return)
        viewModelScope.launch(Dispatchers.Default) { hub.perform { account.closePairing() } }
        update { copy(pairing = PairingUi()) }
        showHome()
    }

    fun pairWith(device: NearbyDevice) {
        val (account, hub) = (account ?: return) to (hub ?: return)
        if (state.pairing.connecting || state.pairing.sas != null) return
        update { copy(pairing = pairing.copy(connecting = true, failure = null)) }
        viewModelScope.launch {
            // The preferred transport first; the next one if it cannot reach the device.
            for (peer in device.peers) {
                try {
                    withContext(Dispatchers.IO) {
                        val connection = hub.attach(peer.connect(), peer.kind)
                        update { copy(pairing = pairing.copy(attempt = connection)) }
                        hub.perform { account.pairNearby(connection.toULong()) }
                    }
                    return@launch
                } catch (e: Exception) {
                    if (e !is IOException && e !is SecurityException) throw e
                    if (BuildConfig.DEBUG) Log.w(TAG, "could not reach ${device.label} over ${peer.kind}", e)
                }
            }
            update { copy(pairing = pairing.copy(connecting = false, failure = R.string.pairing_unreachable)) }
        }
    }

    fun confirmSas() {
        val (account, hub) = (account ?: return) to (hub ?: return)
        val sas = state.pairing.sas ?: return
        update { copy(pairing = pairing.copy(sas = sas.copy(confirmed = true))) }
        viewModelScope.launch(Dispatchers.Default) { hub.perform { account.confirmPairing(sas.connection.toULong()) } }
    }

    fun rejectSas() {
        val (account, hub) = (account ?: return) to (hub ?: return)
        val sas = state.pairing.sas ?: return
        update { copy(pairing = pairing.copy(sas = null, connecting = false)) }
        viewModelScope.launch(Dispatchers.Default) { hub.perform { account.rejectPairing(sas.connection.toULong()) } }
    }

    fun dismissPairingResult() = update { copy(pairing = pairing.copy(pairedWith = null, failure = null)) }

    private fun onNetEvent(event: NetEvent) {
        when (event) {
            is NetEvent.ShowSas -> {
                val current = state.pairing.sas
                if (current != null && current.connection != event.connection) {
                    // One comparison at a time: turn away a second device that picked us meanwhile.
                    val (account, hub) = (account ?: return) to (hub ?: return)
                    viewModelScope.launch(Dispatchers.Default) {
                        hub.perform { account.rejectPairing(event.connection.toULong()) }
                    }
                } else {
                    update { copy(pairing = pairing.copy(connecting = false, sas = SasPrompt(event.connection, event.emoji))) }
                }
            }

            is NetEvent.Paired -> {
                hideInvite()
                update { copy(pairing = pairing.copy(connecting = false, sas = null, pairedWith = event.contact.displayName)) }
                viewModelScope.launch {
                    refreshContacts()
                    refreshRequests()
                }
            }
            is NetEvent.ContactRequested -> viewModelScope.launch { refreshRequests() }
            is NetEvent.MemberProposed -> {
                val name = state.contacts.find { it.id == event.contactId }?.displayName ?: return
                update { copy(memberProposal = ProposalUi(event.contactId, name, event.proposal)) }
            }
            is NetEvent.MemberProposalDeclined -> update { copy(notice = R.string.propose_member_declined) }

            // Links: see runtime.linked. Arrivals while locked: shown after the unlock, from the database.
            // Moves between transports are the runtime's business.
            // A new path's link may carry what an old one to the same contact did not.
            is NetEvent.LinkUp -> startCallOnceOverWifi(runtime.linked.value)
            is NetEvent.PathFailed -> pathFailed(event.contactId, event.pathClass)
            is NetEvent.MessageArrived -> schedulePreviews()
            is NetEvent.LinkDown, is NetEvent.WaitingForWifi,
            is NetEvent.MoveRequested, is NetEvent.HotspotOffered, is NetEvent.MoveDeclined -> Unit
            // Calls and talks: see runtime.voice.
            is NetEvent.CallRinging, is NetEvent.CallReached, is NetEvent.CallAccepted, is NetEvent.CallEnded,
            is NetEvent.VideoStateChanged, is NetEvent.KeyFrameRequested,
            is NetEvent.TalkStarted, is NetEvent.TalkEnded, is NetEvent.GroupTalkStarted,
            is NetEvent.GroupCallRinging, is NetEvent.GroupCallChanged, is NetEvent.ChannelTalkStarted -> Unit
            NetEvent.ChannelPeersChanged -> viewModelScope.launch { refreshWalkie() }
            is NetEvent.AttestationChanged -> viewModelScope.launch { refreshContacts() }
            is NetEvent.MessageReceived -> updateChat(event.message)
            is NetEvent.MessageUpdated -> updateChat(event.message)
            is NetEvent.GroupChanged -> viewModelScope.launch {
                refreshGroups()
                reloadGroupChat(event.group)
            }
            is NetEvent.GroupMessageReceived -> updateGroupChat(event.message)
            is NetEvent.GroupMessageUpdated -> updateGroupChat(event.message)
            is NetEvent.GroupMessageArrived -> schedulePreviews()

            is NetEvent.Failed -> {
                val ours = event.connection == state.pairing.sas?.connection ||
                    event.connection == state.pairing.attempt
                if (ours) {
                    update { copy(pairing = pairing.copy(connecting = false, sas = null, failure = event.reason.messageRes())) }
                }
            }
        }
    }

    private fun showHome() {
        val account = checkNotNull(account)
        update {
            copy(
                screen = Screen.Home(account.displayName(), account.airchatId()),
                busy = false,
                error = null,
                biometricAvailable = biometricAvailable(),
                biometricEnabled = store.biometricEnabled(),
                contacts = account.contacts(),
                groups = account.groups(),
                walkie = walkie.copy(channels = account.channels(), peers = account.channelPeers()),
                receiveWhileLocked = runtime.receiveWhileLocked,
                acceptRequests = runtime.acceptRequests,
                sentRequests = account.sentRequests(),
                contactRequests = account.contactRequests(),
                previews = account.chatPreviews(),
            )
        }
        updateRadios()
    }

    private fun showLocked() {
        update {
            copy(
                screen = Screen.Locked,
                busy = false,
                biometricAvailable = biometricAvailable(),
                biometricEnabled = store.biometricEnabled(),
            )
        }
        tickLockout()
    }

    private fun tickLockout() {
        lockoutTicker?.cancel()
        lockoutTicker = viewModelScope.launch {
            while (true) {
                val remaining = withContext(Dispatchers.IO) { store.lockoutRemainingMs() }
                update { copy(lockoutSeconds = (remaining + 999) / 1000) }
                if (remaining == 0L) break
                delay(minOf(remaining, 1000))
            }
        }
    }

    /**
     * Runs a blocking core/Keystore operation off the main thread. The PIN is turned into bytes only
     * here and wiped afterwards; the UI's own copy is cleared by the caller.
     */
    private fun runBusy(pin: CharSequence? = null, block: suspend (ByteArray) -> Unit) {
        if (state.busy) return
        // Copy now: the caller clears its text field as soon as this returns.
        val pinBytes = pin?.toString()?.encodeToByteArray() ?: ByteArray(0)
        update { copy(busy = true, error = null) }
        viewModelScope.launch {
            try {
                withContext(Dispatchers.Default) { block(pinBytes) }
            } catch (e: CoreException) {
                update { copy(busy = false, error = e.messageRes()) }
                if (e is CoreException.WrongCredential) tickLockout()
            } catch (_: KeyLostException) {
                update { copy(busy = false, error = R.string.error_device_key_lost) }
            } catch (e: Exception) {
                // Debug builds only: release logs must never carry anything about the user's data.
                if (BuildConfig.DEBUG) Log.w(TAG, "operation failed", e)
                update { copy(busy = false, error = R.string.error_unexpected) }
            } finally {
                pinBytes.fill(0)
            }
        }
    }

    private fun biometricAvailable() = biometricManager.canAuthenticate(BIOMETRIC_STRONG) == BiometricManager.BIOMETRIC_SUCCESS

    private inline fun update(transform: UiState.() -> UiState) {
        state = state.transform()
    }

    private companion object {
        const val TAG = "AirChat"
        /** How often the position of a playing voice message is read. */
        const val VOICE_POSITION_EVERY_MS = 200L
        /** Downloads this large ask for fast Wi-Fi when the link runs over Bluetooth. */
        /** A call asked for over Bluetooth is given up if Wi-Fi does not come within this time. */
        const val CALL_WAITS_FOR_WIFI_MS = 120_000L
        const val VIEWER_MAX_PX = 2048
        const val NOTICE_MS = 3_000L
        // Events of one change come together: the chat list is read once they settled.
        const val PREVIEWS_DELAY_MS = 150L
        /** How long to look for the device of a scanned QR invite. */
        const val INVITE_FIND_MS = 20_000L
    }
}

private fun ByteArray.toHex() = joinToString("") { "%02x".format(it) }

@StringRes
private fun Failure.messageRes(): Int = when (this) {
    Failure.REJECTED -> R.string.pairing_failed_rejected
    Failure.AUTHENTICATION_FAILED -> R.string.pairing_failed_authentication
    Failure.INVALID_INVITE -> R.string.pairing_failed_invite
    Failure.NOT_ACCEPTING -> R.string.pairing_failed_not_accepting
    Failure.CONNECTION_LOST -> R.string.pairing_failed_connection_lost
    Failure.BLOCKED -> R.string.pairing_failed_blocked
    Failure.PROTOCOL -> R.string.pairing_failed_generic
}

@StringRes
private fun CoreException.messageRes(): Int = when (this) {
    is CoreException.WrongCredential -> R.string.error_wrong_pin
    is CoreException.PinTooShort -> R.string.error_pin_too_short
    is CoreException.InvalidDisplayName -> R.string.error_invalid_name
    is CoreException.CorruptKeyRecord -> R.string.error_corrupt_record
    else -> R.string.error_unexpected
}

/** A voice message playing: which file, whether it plays now, where it is and how long it is. */
data class VoicePlayback(val file: Long, val playing: Boolean, val positionMs: Long, val durationMs: Long)
