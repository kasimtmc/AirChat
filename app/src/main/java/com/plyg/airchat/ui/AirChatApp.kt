package com.plyg.airchat.ui

import android.Manifest
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Surface
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import com.plyg.airchat.R
import com.plyg.airchat.core.groupFile
import com.plyg.airchat.core.ContactState
import com.plyg.airchat.runtime.CallPhase
import com.plyg.airchat.runtime.CallUi
import com.plyg.airchat.ui.screens.AddMembersDialog
import com.plyg.airchat.ui.screens.AddNearbyScreen
import com.plyg.airchat.ui.screens.BiometricOfferScreen
import com.plyg.airchat.ui.screens.CallScreen
import com.plyg.airchat.ui.screens.ChatScreen
import com.plyg.airchat.ui.screens.FileViewer
import com.plyg.airchat.ui.screens.GroupChatScreen
import com.plyg.airchat.ui.screens.MainScreen
import com.plyg.airchat.ui.screens.LockScreen
import com.plyg.airchat.ui.screens.MAX_MEMBERS
import com.plyg.airchat.ui.screens.MemberProposalDialog
import com.plyg.airchat.ui.screens.OnboardingScreen
import com.plyg.airchat.ui.screens.TalkBanner
import com.plyg.airchat.ui.screens.WalkieScreen

@Composable
fun AirChatApp(viewModel: AppViewModel, biometric: BiometricPrompter) {
    val state = viewModel.state
    val remoteFormat by viewModel.remoteVideoFormat.collectAsState()
    val memberFormats by viewModel.memberVideoFormats.collectAsState()
    val voicePlayback by viewModel.voicePlayback.collectAsState()
    val promptTitle = stringResource(R.string.biometric_prompt_title)
    val usePin = stringResource(R.string.use_pin)
    val cancel = stringResource(R.string.cancel)
    // Once, when the account is first open: notifications, and what finding nearby devices needs.
    val askOnce = rememberLauncherForActivityResult(ActivityResultContracts.RequestMultiplePermissions()) {
        viewModel.onPermissionsResult()
    }
    val home = state.screen is Screen.Home
    LaunchedEffect(home) {
        if (home) viewModel.permissionsToAskOnce().takeIf { it.isNotEmpty() }?.let { askOnce.launch(it.toTypedArray()) }
    }
    // Again whenever the user wants to find someone and something is missing.
    val transportPermissions = rememberLauncherForActivityResult(ActivityResultContracts.RequestMultiplePermissions()) {
        viewModel.onPermissionsResult()
        viewModel.openAddNearby()
    }
    val addNearby = {
        val missing = viewModel.missingTransportPermissions()
        if (missing.isNotEmpty()) transportPermissions.launch(missing.toTypedArray()) else viewModel.openAddNearby()
    }
    // The microphone, asked before the first call or talk; [then] learns whether it was granted.
    var afterMicrophone by remember { mutableStateOf<((Boolean) -> Unit)?>(null) }
    val microphone = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) { granted ->
        afterMicrophone?.invoke(granted)
        afterMicrophone = null
    }
    val withMicrophone = { then: (Boolean) -> Unit ->
        if (viewModel.microphonePermitted()) {
            then(true)
        } else {
            afterMicrophone = then
            microphone.launch(Manifest.permission.RECORD_AUDIO)
        }
    }
    // The camera, asked before reading a QR code or turning it on in a call; [then] learns whether
    // it was granted.
    var afterCamera by remember { mutableStateOf<((Boolean) -> Unit)?>(null) }
    val camera = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) { granted ->
        afterCamera?.invoke(granted)
        afterCamera = null
    }
    val askCamera = { then: (Boolean) -> Unit ->
        if (viewModel.cameraPermitted()) {
            then(true)
        } else {
            afterCamera = then
            camera.launch(Manifest.permission.CAMERA)
        }
    }
    val withCamera = { then: () -> Unit -> askCamera { granted -> if (granted) then() else viewModel.cameraDenied() } }
    // Answered from the notification: once the microphone is settled. Without it, only listening.
    LaunchedEffect(state.answerPending) {
        if (state.answerPending) withMicrophone { viewModel.answerCall() }
    }

    NoPersonalizedLearning {
        Surface(Modifier.fillMaxSize()) {
            Box(Modifier.fillMaxSize()) {
                when (val screen = state.screen) {
                    Screen.Loading -> Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                        CircularProgressIndicator()
                    }

                    Screen.Onboarding -> OnboardingScreen(state, onCreate = viewModel::createAccount)

                    Screen.Locked -> LockScreen(
                        state = state,
                        onUnlock = viewModel::unlockWithPin,
                        onBiometric = {
                            viewModel.biometricUnlockCipher()?.let { cipher ->
                                biometric.authenticate(cipher, promptTitle, usePin, viewModel::unlockWithBiometric)
                            }
                        },
                        onReset = viewModel::reset,
                    )

                    Screen.OfferBiometric -> BiometricOfferScreen(
                        state = state,
                        onEnable = {
                            biometric.authenticate(
                                viewModel.biometricEnrollCipher(),
                                promptTitle,
                                cancel,
                                viewModel::enableBiometric,
                            )
                        },
                        onSkip = viewModel::skipBiometric,
                    )

                    Screen.AddNearby -> AddNearbyScreen(
                        pairing = state.pairing,
                        onPick = viewModel::pairWith,
                        onConfirmSas = viewModel::confirmSas,
                        onRejectSas = viewModel::rejectSas,
                        onDismissResult = viewModel::dismissPairingResult,
                        onClose = viewModel::closeAddNearby,
                        onShowCode = viewModel::showInvite,
                        onHideCode = viewModel::hideInvite,
                        onScan = withCamera,
                        onScanned = viewModel::pairWithCode,
                    )

                    Screen.Chat -> state.chat?.let { chat ->
                        ChatScreen(
                            chat = chat,
                            via = state.linked[chat.contactId],
                            reachable = chat.contactId in state.linked || state.providers > 0,
                            error = state.error,
                            notice = state.notice,
                            onSend = viewModel::sendMessage,
                            onSendFile = viewModel::sendFile,
                            onDownload = viewModel::downloadFile,
                            onOpen = viewModel::openFile,
                            onBack = viewModel::closeChat,
                            onDelete = { keepHistory -> viewModel.deleteContact(chat.contactId, keepHistory) },
                            onBlock = { viewModel.blockContact(chat.contactId) },
                            emergencyGroups = state.emergencyGroups,
                            emergencyResult = state.emergencyResult,
                            onAskEmergencyExit = viewModel::askEmergencyExit,
                            onEmergencyExit = viewModel::emergencyExit,
                            onDismissEmergencyExit = viewModel::dismissEmergencyExit,
                            onUnblock = { viewModel.unblockContact(chat.contactId) },
                            onPermissions = { viewModel.setPermissions(chat.contactId, it) },
                            talk = state.talk,
                            talkRefused = state.talkRefused,
                            onCall = {
                                withMicrophone { granted ->
                                    if (granted) viewModel.call(chat.contactId) else viewModel.microphoneDenied()
                                }
                            },
                            // Without the camera, a video call starts with the camera off.
                            onVideoCall = {
                                withMicrophone { granted ->
                                    if (granted) askCamera { viewModel.call(chat.contactId, video = true) } else viewModel.microphoneDenied()
                                }
                            },
                            onTalkStart = {
                                if (viewModel.microphonePermitted()) {
                                    viewModel.startTalk(chat.contactId)
                                } else {
                                    withMicrophone { granted -> if (!granted) viewModel.microphoneDenied() }
                                    false
                                }
                            },
                            onTalkEnd = viewModel::endTalk,
                            onMoveToWifi = viewModel::moveToWifi,
                            waitingForWifi = chat.contactId in state.waitingForWifi,
                            ownName = viewModel.displayName(),
                            others = state.contacts,
                            onProposeMember = viewModel::proposeMember,
                            onTryAgain = viewModel::tryMessageAgain,
                            voicePlayback = voicePlayback,
                            onToggleVoice = { message ->
                                message.attachment?.let { viewModel.toggleVoice(message.id, it.size.toLong()) }
                            },
                            onMute = { viewModel.muteContact(chat.contactId, it) },
                        )
                        state.viewer?.let { viewer ->
                            FileViewer(
                                viewer = viewer,
                                notice = state.notice,
                                error = state.error,
                                onClose = viewModel::closeViewer,
                                onExport = { viewModel.beginExport(viewer.file) },
                                onExportTo = viewModel::exportTo,
                            )
                        }
                    }

                    Screen.GroupChat -> state.groupChat?.let { chat ->
                        GroupChatScreen(
                            chat = chat,
                            contacts = state.contacts,
                            error = state.error,
                            onSend = viewModel::sendGroupMessage,
                            onBack = viewModel::closeGroup,
                            onAddMembers = viewModel::addGroupMembers,
                            onRemoveMember = viewModel::removeGroupMember,
                            onLeave = viewModel::leaveGroup,
                            onDeleteForEveryone = viewModel::deleteGroupForEveryone,
                            onDeleteChat = viewModel::deleteGroupChat,
                            onAddMembersForCall = viewModel::addGroupMembersForCall,
                            onSetAdmin = viewModel::setGroupAdmin,
                            onTryAgain = viewModel::tryGroupMessageAgain,
                            voicePlayback = voicePlayback,
                            onToggleVoice = { message ->
                                message.attachment?.let { viewModel.toggleVoice(groupFile(message.id), it.size.toLong()) }
                            },
                            inCall = state.call?.let { it.groupId == chat.group.id && it.phase == CallPhase.ACTIVE } == true,
                            talk = state.talk,
                            talkRefused = state.talkRefused,
                            onTalkStart = {
                                if (viewModel.microphonePermitted()) {
                                    viewModel.startGroupTalk(chat.group.id)
                                } else {
                                    withMicrophone { granted -> if (!granted) viewModel.microphoneDenied() }
                                    false
                                }
                            },
                            onTalkEnd = viewModel::endTalk,
                            onCall = {
                                withMicrophone { granted ->
                                    if (granted) viewModel.callGroup(chat.group.id) else viewModel.microphoneDenied()
                                }
                            },
                            onPtt = viewModel::setGroupPtt,
                            membersNearby = chat.members.any { it.rowId != null && it.rowId in state.linked },
                            onSendFile = viewModel::sendGroupFile,
                            onDownload = viewModel::downloadGroupFile,
                            onOpen = viewModel::openGroupFile,
                            onMute = viewModel::muteGroup,
                        )
                        state.viewer?.let { viewer ->
                            FileViewer(
                                viewer = viewer,
                                notice = state.notice,
                                error = state.error,
                                onClose = viewModel::closeViewer,
                                onExport = { viewModel.beginExport(viewer.file) },
                                onExportTo = viewModel::exportTo,
                            )
                        }
                    }

                    is Screen.Home -> MainScreen(
                        state = state,
                        home = screen,
                        onSelectTab = viewModel::selectTab,
                        onLock = viewModel::lock,
                        onAddNearby = addNearby,
                        onOpenChat = viewModel::openChat,
                        onOpenGroup = viewModel::openGroup,
                        onCreateGroup = viewModel::createGroup,
                        onRequestContact = viewModel::requestContact,
                        onCancelRequest = viewModel::cancelRequest,
                        onApproveRequest = viewModel::approveRequest,
                        onDeclineRequest = viewModel::declineRequest,
                        onDismissRequestError = viewModel::dismissRequestError,
                        onReceiveWhileLockedChange = viewModel::setReceiveWhileLocked,
                        onAcceptRequestsChange = viewModel::setAcceptRequests,
                        onAirProviderChange = viewModel::setAirProvider,
                        onTransportChange = viewModel::setTransportEnabled,
                        onDirectContactLinksChange = viewModel::setDirectContactLinks,
                        onBiometricChange = { enable ->
                            if (enable) {
                                biometric.authenticate(
                                    viewModel.biometricEnrollCipher(),
                                    promptTitle,
                                    cancel,
                                    viewModel::enableBiometric,
                                )
                            } else {
                                viewModel.disableBiometric()
                            }
                        },
                        walkie = {
                            WalkieScreen(
                                walkie = state.walkie,
                                talk = state.talk,
                                talkRefused = state.talkRefused,
                                error = state.error,
                                onBack = viewModel::closeWalkie,
                                onCreate = viewModel::createChannel,
                                onScan = withCamera,
                                onScanned = viewModel::joinChannelByQr,
                                onPassword = viewModel::joinChannelByPassword,
                                onTune = viewModel::tuneChannel,
                                onShare = viewModel::shareChannel,
                                onDismissShare = viewModel::dismissShare,
                                onDelete = viewModel::deleteChannel,
                                onTalkStart = {
                                    if (viewModel.microphonePermitted()) {
                                        viewModel.startChannelTalk()
                                    } else {
                                        withMicrophone { granted -> if (!granted) viewModel.microphoneDenied() }
                                        false
                                    }
                                },
                                onTalkEnd = viewModel::endTalk,
                                onMute = viewModel::muteChannel,
                            )
                        },
                    )
                }
                // A contact proposes a group of the two of you and someone else (M-3).
                state.memberProposal?.takeIf { state.screen != Screen.Locked }?.let { asked ->
                    MemberProposalDialog(asked, onAnswer = viewModel::answerMemberProposal)
                }
                // Someone talks while the user is elsewhere: who, over every screen but that conversation.
                val talk = state.talk?.takeIf { !it.talking }
                val unlocked = state.screen != Screen.Locked
                val inTalkersChat = when {
                    talk?.channelId != null -> state.screen is Screen.Home && state.homeTab == HomeTab.WALKIE
                    talk?.groupId != null -> state.screen == Screen.GroupChat && state.groupChat?.group?.id == talk.groupId
                    else -> state.screen == Screen.Chat && state.chat?.contactId == talk?.contactId
                }
                if (talk != null && !inTalkersChat && state.call == null) {
                    // Contacts and groups are empty while locked: then the banner names nobody.
                    if (talk.channelId != null) {
                        val channel = state.walkie.channels.find { it.id == talk.channelId }?.takeIf { unlocked }
                        val someone = stringResource(R.string.walkie_someone)
                        TalkBanner(
                            name = channel?.let { state.walkie.peers.find { it.id == talk.contactId }?.name?.ifBlank { someone } ?: someone },
                            onOpen = channel?.let { { viewModel.openWalkie() } },
                            channelName = channel?.name,
                            modifier = Modifier.align(Alignment.TopCenter),
                        )
                    } else if (talk.groupId != null) {
                        val group = state.groups.find { it.id == talk.groupId }?.takeIf { unlocked }
                        TalkBanner(
                            name = group?.let { state.voiceNames[talk.contactId] ?: stringResource(R.string.group_former_member) },
                            onOpen = group?.let { { viewModel.openGroup(it) } },
                            groupName = group?.name,
                            modifier = Modifier.align(Alignment.TopCenter),
                        )
                    } else {
                        val contact = state.contacts.find { it.id == talk.contactId }?.takeIf { unlocked }
                        TalkBanner(
                            name = contact?.displayName,
                            onOpen = contact?.let { { viewModel.openChat(it) } },
                            modifier = Modifier.align(Alignment.TopCenter),
                        )
                    }
                }
                // A call shows over everything, the lock screen too, but names the caller only when unlocked.
                state.call?.let { call ->
                    val group = call.groupId?.let { id -> state.groups.find { it.id == id } }
                    var adding by remember(call.id) { mutableStateOf(false) }
                    CallScreen(
                        call = call,
                        name = (if (call.groupId != null) group?.name else state.contacts.find { it.id == call.contactId }?.displayName)
                            ?.takeIf { unlocked },
                        detail = if (group != null && unlocked) groupCallDetail(call, state.voiceNames) else null,
                        unlocked = unlocked,
                        remoteFormat = remoteFormat,
                        onAnswer = {
                            withMicrophone { if (call.video) askCamera { viewModel.answerCall() } else viewModel.answerCall() }
                        },
                        onHangUp = viewModel::hangUp,
                        onMute = viewModel::setMuted,
                        onSpeaker = viewModel::setSpeaker,
                        onCamera = { on -> if (on) withCamera { viewModel.setCamera(true) } else viewModel.setCamera(false) },
                        onSwitchCamera = viewModel::switchCamera,
                        onLocalPreview = viewModel::setLocalPreview,
                        onRemoteView = viewModel::setRemoteView,
                        onAddPeople = { adding = true }.takeIf {
                            group?.admin == true && unlocked && call.phase == CallPhase.ACTIVE &&
                                group.members.toInt() < MAX_MEMBERS
                        },
                        memberFormats = memberFormats,
                        memberNames = state.voiceNames,
                        onMemberView = viewModel::setMemberView,
                    )
                    if (adding && group != null) {
                        AddMembersDialog(
                            // The call names its members by row, and a contact's row is its id.
                            candidates = state.contacts.filter { it.state == ContactState.ACTIVE && it.id !in state.voiceNames },
                            room = MAX_MEMBERS - group.members.toInt(),
                            inCall = true,
                            fromCall = true,
                            onDismiss = { adding = false },
                            onAdd = { ids, expires, forCall ->
                                adding = false
                                viewModel.addToCallGroup(ids, expires, forCall)
                            },
                        )
                    }
                }
            }
        }
    }
}

/** Who calls a group, or who is in the call with this device. */
@Composable
private fun groupCallDetail(call: CallUi, names: Map<Long, String>): String? {
    val unknown = stringResource(R.string.group_former_member)
    return when (call.phase) {
        CallPhase.RINGING_HERE -> stringResource(R.string.group_call_ringing, names[call.contactId] ?: unknown)
        CallPhase.CALLING -> stringResource(R.string.group_call_waiting)
        CallPhase.ACTIVE -> {
            val shown = call.participants.take(3).map { names[it] ?: unknown }
            val more = call.participants.size - shown.size
            (shown + listOfNotNull(stringResource(R.string.group_call_others, more).takeIf { more > 0 })).joinToString(", ")
        }
        else -> null
    }
}
