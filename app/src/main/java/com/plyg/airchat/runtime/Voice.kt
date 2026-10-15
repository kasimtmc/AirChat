package com.plyg.airchat.runtime

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.graphics.SurfaceTexture
import android.os.SystemClock
import android.util.Log
import androidx.core.content.ContextCompat
import com.plyg.airchat.BuildConfig
import com.plyg.airchat.audio.OggOpus
import com.plyg.airchat.audio.VOICE_RATE
import com.plyg.airchat.audio.VoiceEngine
import com.plyg.airchat.core.Account
import com.plyg.airchat.core.CoreException
import com.plyg.airchat.core.EndReason
import com.plyg.airchat.core.Started
import com.plyg.airchat.core.VideoState
import com.plyg.airchat.core.maxVoiceBytes
import com.plyg.airchat.net.ConnectionHub
import com.plyg.airchat.net.NetEvent
import com.plyg.airchat.net.TransportKind
import com.plyg.airchat.net.VideoFrame
import com.plyg.airchat.video.CameraSender
import com.plyg.airchat.video.VideoFormat
import com.plyg.airchat.video.VideoReceiver
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import java.util.concurrent.ConcurrentHashMap

enum class CallPhase {
    /** Asked; not ringing there yet. */
    CALLING,
    RINGING_THERE,
    RINGING_HERE,
    ACTIVE,
    /** Shown for a moment, with the reason. */
    ENDED,
}

class CallUi(
    val id: ByteArray,
    /** The other side; for a group call, who called (0 for this device's own). */
    val contactId: Long,
    val outgoing: Boolean,
    val phase: CallPhase,
    /** [SystemClock.elapsedRealtime] when it was answered. */
    val answeredAt: Long? = null,
    val muted: Boolean = false,
    val speaker: Boolean = false,
    val ended: EndReason? = null,
    /** A group call: the group, and who else is in it (contact or fellow-member rows). */
    val groupId: Long? = null,
    val participants: List<Long> = emptyList(),
    /** Started (or rings) as a video call (rust/airchat-protocol/docs/protocol.md §8.6). */
    val video: Boolean = false,
    /** This device's camera is on, by the user's choice. */
    val camera: Boolean = false,
    val frontCamera: Boolean = true,
    /** The contact's camera. */
    val remoteVideo: VideoState = VideoState.OFF,
    /** The camera is on, but the link runs over Bluetooth: video waits for Wi-Fi. */
    val videoWaits: Boolean = false,
    /** In a group call, the participants' cameras, by row (rust/airchat-protocol/docs/protocol.md §9.9). */
    val memberCameras: Map<Long, VideoState> = emptyMap(),
) {
    /** In a group call, whether this device may turn its camera on: fewer than four others have. */
    val groupCameraRoom: Boolean get() = memberCameras.count { it.value == VideoState.ON } < MAX_GROUP_CAMERAS

    fun copy(
        phase: CallPhase = this.phase,
        answeredAt: Long? = this.answeredAt,
        muted: Boolean = this.muted,
        speaker: Boolean = this.speaker,
        ended: EndReason? = this.ended,
        participants: List<Long> = this.participants,
        camera: Boolean = this.camera,
        frontCamera: Boolean = this.frontCamera,
        remoteVideo: VideoState = this.remoteVideo,
        videoWaits: Boolean = this.videoWaits,
        memberCameras: Map<Long, VideoState> = this.memberCameras,
    ) = CallUi(
        id, contactId, outgoing, phase, answeredAt, muted, speaker, ended, groupId, participants,
        video, camera, frontCamera, remoteVideo, videoWaits, memberCameras,
    )

    companion object {
        /** Cameras on at once in a group call, at most (§9.9). */
        const val MAX_GROUP_CAMERAS = 4
    }
}

/**
 * Push-to-talk with a contact, or in a group: this device talking, or hearing [contactId] (a contact,
 * or for a group a fellow member's row; 0 while this device talks to a group).
 */
class TalkUi(
    val id: ByteArray,
    val contactId: Long,
    val talking: Boolean,
    val groupId: Long? = null,
    /** On the tuned walkie-talkie channel; [contactId] names the member in `channelPeers`. */
    val channelId: Long? = null,
    /** They do not take push-to-talk now: what is said is recorded as a voice message (V-3). */
    val voiceMessage: Boolean = false,
)

/** A talk the other side would not hear live, as an Ogg Opus file to send in its place. */
class VoiceMessage(val contactId: Long, val groupId: Long?, val ogg: ByteArray, val durationMs: Long)

/** How this device's last talk ended, when the contact (or the group, or the channel) cut it short. */
class TalkRefusal(val contactId: Long, val reason: EndReason, val groupId: Long? = null, val channelId: Long? = null)

/**
 * Voice and video calls and push-to-talk (rust/airchat-protocol/docs/protocol.md §8.5, §8.6). Lives in the runtime, not a
 * screen, because calls ring and go on in the background and while AirChat is locked. Main thread,
 * except [onAudio] and [onVideo].
 *
 * Video runs only while AirChat is unlocked (the picture shows who calls) and the call screen shows
 * it, and is sent only while the link runs over Wi-Fi (T-3); otherwise the camera is paused. In a
 * group call the core sends it over the links that carry video and passes the others' on (§9.9);
 * each participant's picture has a decoder of its own.
 */
class Voice(
    private val app: Context,
    private val scope: CoroutineScope,
    private val notifications: Notifications,
    /** The foreground service must say it uses the microphone while it does (Android 11+). */
    private val onMicrophone: (Boolean) -> Unit,
    /** What carries the link to a contact now; null without one. */
    private val linkOf: (Long) -> TransportKind?,
    /** Asks to move the link to a contact to fast Wi-Fi for a video call; returns whether it asked. */
    private val requestFastLink: (Long) -> Boolean,
    /** Whether the link to a contact may carry video: Wi-Fi, or a path through Air Providers that does. */
    private val carriesVideo: (Long) -> Boolean,
) {
    var account: Account? = null
    var hub: ConnectionHub? = null

    private val ringer = Ringer(app)
    private val _call = MutableStateFlow<CallUi?>(null)
    val call: StateFlow<CallUi?> = _call
    private val _talk = MutableStateFlow<TalkUi?>(null)
    val talk: StateFlow<TalkUi?> = _talk
    private val _talkRefused = MutableStateFlow<TalkRefusal?>(null)
    val talkRefused: StateFlow<TalkRefusal?> = _talkRefused
    private val _voiceMessages = MutableSharedFlow<VoiceMessage>(extraBufferCapacity = 4)
    /** Talks that became voice messages, to send. */
    val voiceMessages: SharedFlow<VoiceMessage> = _voiceMessages

    /** The Opus packets of this device's talk so far, to send them as a voice message if need be. */
    @Volatile private var recording: Recording? = null
    /** Not heard live any more: what the microphone takes only goes into [recording]. */
    @Volatile private var voiceOnly = false

    @Volatile private var engine: VoiceEngine? = null
    @Volatile private var engineStream: ByteArray? = null

    // Video: this device's camera, the contact's picture, and the views they show in.
    private var unlocked = false
    @Volatile private var sender: CameraSender? = null
    @Volatile private var receiver: VideoReceiver? = null
    private var previewTexture: SurfaceTexture? = null
    private var remoteTexture: SurfaceTexture? = null
    private var remoteSurface: android.view.Surface? = null
    /** The camera state the core last heard; null at the start of a call. */
    private var announced: VideoState? = null
    private var askedForFastLink = false
    private val _remoteFormat = MutableStateFlow<VideoFormat?>(null)
    /** The contact's picture as it arrives, for the view that shows it. */
    val remoteFormat: StateFlow<VideoFormat?> = _remoteFormat
    /** The call whose video is being sent, and to whom; read on the camera thread. */
    @Volatile private var videoStream: ByteArray? = null
    @Volatile private var videoContact = 0L
    // A group call: its participants (whose links' backlog says whether video keeps up), and each
    // one's picture, its decoder and the texture it is drawn on.
    @Volatile private var videoGroup = false
    @Volatile private var videoMembers: List<Long> = emptyList()
    private val memberReceivers = ConcurrentHashMap<Long, VideoReceiver>()
    private val memberViews = mutableMapOf<Long, Pair<SurfaceTexture, android.view.Surface>>()
    private val _memberFormats = MutableStateFlow<Map<Long, VideoFormat>>(emptyMap())
    /** Each group call participant's picture as it arrives, by row, for the views that show them. */
    val memberFormats: StateFlow<Map<Long, VideoFormat>> = _memberFormats
    // Sending video as fast as the link takes it, on the camera thread.
    private var skipping = false
    private var bitrate = CameraSender.START_BITRATE
    private var slowedAt = 0L
    private var raisedAt = 0L
    private var keyAskedAt = 0L

    fun microphonePermitted() =
        ContextCompat.checkSelfPermission(app, Manifest.permission.RECORD_AUDIO) == PackageManager.PERMISSION_GRANTED

    fun cameraPermitted() =
        ContextCompat.checkSelfPermission(app, Manifest.permission.CAMERA) == PackageManager.PERMISSION_GRANTED

    /** A call (ringing or under way) or a talk keeps the account from locking automatically. */
    val busy: Boolean get() = _call.value?.let { it.phase != CallPhase.ENDED } == true || _talk.value != null

    // Calls.

    /** Calls a contact; a video call starts with the camera on. */
    fun startCall(contactId: Long, video: Boolean = false): Boolean {
        val (account, hub) = (account ?: return false) to (hub ?: return false)
        if (_call.value?.phase.let { it != null && it != CallPhase.ENDED }) return false
        val started = try {
            hub.performFor { account.startCall(contactId, video).let { it to it.actions } }
        } catch (e: CoreException) {
            if (BuildConfig.DEBUG) Log.w(TAG, "could not call", e)
            null
        } ?: return false
        endTalkLocally()
        _call.value = CallUi(
            started.id,
            contactId,
            outgoing = true,
            phase = CallPhase.CALLING,
            video = video,
            camera = video && cameraPermitted(),
            speaker = video,
        )
        updateVideo()
        return true
    }

    /** Calls the members of a group linked now; it rings for them, and for those who come by. */
    fun startGroupCall(groupId: Long): Boolean {
        val (account, hub) = (account ?: return false) to (hub ?: return false)
        if (_call.value?.phase.let { it != null && it != CallPhase.ENDED }) return false
        val started = try {
            hub.performFor { account.startGroupCall(groupId).let { it to it.actions } }
        } catch (e: CoreException) {
            if (BuildConfig.DEBUG) Log.w(TAG, "could not call the group", e)
            null
        } ?: return false
        endTalkLocally()
        // Calling until the first member joins; then the microphone opens.
        _call.value = CallUi(started.id, 0, outgoing = true, phase = CallPhase.CALLING, groupId = groupId)
        return true
    }

    fun answer() {
        val call = _call.value?.takeIf { it.phase == CallPhase.RINGING_HERE } ?: return
        val (account, hub) = (account ?: return) to (hub ?: return)
        stopRinging()
        try {
            if (call.groupId != null) {
                hub.perform { account.joinGroupCall(call.id) }
            } else {
                hub.perform { account.answerCall(call.id) }
            }
        } catch (_: CoreException) {
            return ended(call.id, EndReason.LOST)
        }
        // What the call learned meanwhile (who else is in a group call, the contact's camera) stays.
        _call.value = (ours(call.id) ?: call).copy(
            phase = CallPhase.ACTIVE,
            answeredAt = SystemClock.elapsedRealtime(),
            // A video call is answered with the camera on, if it may be used.
            camera = call.video && cameraPermitted(),
        )
        startEngine(call.id, send = true, play = true, loud = call.video)
        updateVideo()
    }

    /** Hangs up, cancels, or declines a call ringing here. */
    fun hangUp() {
        val call = _call.value ?: return
        if (call.phase == CallPhase.ENDED) return run { _call.value = null }
        val (account, hub) = (account ?: return) to (hub ?: return)
        try {
            hub.perform { account.endCall(call.id) }
        } catch (_: CoreException) {
            ended(call.id, EndReason.HUNG_UP)
        }
    }

    fun setMuted(muted: Boolean) {
        val call = _call.value ?: return
        engine?.muted = muted
        _call.value = call.copy(muted = muted)
    }

    fun setSpeaker(speaker: Boolean) {
        val call = _call.value ?: return
        engine?.speaker = speaker
        _call.value = call.copy(speaker = speaker)
    }

    // Video (rust/airchat-protocol/docs/protocol.md §8.6).

    /** Turns this device's camera on or off; the caller checked the permission. */
    fun setCamera(on: Boolean) {
        val call = _call.value?.takeIf { it.phase != CallPhase.ENDED } ?: return
        if (on && !cameraPermitted()) return
        if (on && call.groupId != null && !call.groupCameraRoom) return
        _call.value = call.copy(camera = on)
        if (on) askedForFastLink = false
        updateVideo()
    }

    fun switchCamera() {
        val call = _call.value?.takeIf { it.camera } ?: return
        _call.value = call.copy(frontCamera = !call.frontCamera)
        sender?.switchCamera()
    }

    /** The local preview's texture while the call screen shows it, null when it goes. */
    fun setLocalPreview(texture: SurfaceTexture?) {
        val old = previewTexture
        if (old === texture) return
        previewTexture = texture
        val sender = sender
        if (sender != null) sender.setPreview(texture) { old?.release() } else old?.release()
        updateVideo()
    }

    /** The texture the contact's picture is drawn on, while shown; null when it goes. */
    fun setRemoteView(texture: SurfaceTexture?) {
        val (old, oldSurface) = remoteTexture to remoteSurface
        if (old === texture) return
        remoteTexture = texture
        remoteSurface = texture?.let { android.view.Surface(it) }
        val release: () -> Unit = {
            oldSurface?.release()
            old?.release()
        }
        val receiver = receiver
        if (receiver != null) receiver.setSurface(remoteSurface, release) else release()
        updateVideo()
    }

    /** The texture a group call participant's picture is drawn on, while shown; null when it goes. */
    fun setMemberView(member: Long, texture: SurfaceTexture?) {
        val old = memberViews[member]
        if (old?.first === texture) return
        val surface = texture?.let { android.view.Surface(it) }
        if (texture != null && surface != null) memberViews[member] = texture to surface else memberViews.remove(member)
        val release: () -> Unit = {
            old?.second?.release()
            old?.first?.release()
        }
        val receiver = memberReceivers[member]
        if (receiver != null) receiver.setSurface(surface, release) else release()
        updateVideo()
    }

    /** AirChat locked or unlocked: video runs only while unlocked. */
    fun setUnlocked(unlocked: Boolean) {
        this.unlocked = unlocked
        updateVideo()
    }

    /** A frame of the contact's video, or of a group call participant's; any thread. */
    fun onVideo(frame: VideoFrame) {
        val receiver = if (videoGroup) memberReceivers[frame.from] else receiver
        if (receiver != null && _call.value?.id contentEquals frame.stream) receiver.push(frame) else frame.data.fill(0)
    }

    /**
     * Starts and stops the camera and the decoder, and tells the core what the camera does, after
     * anything that bears on it changed: the call, the camera choice, the views, the link, the lock.
     */
    private fun updateVideo() {
        val call = _call.value?.takeIf { it.phase != CallPhase.ENDED && it.phase != CallPhase.RINGING_HERE }
        val group = call?.groupId != null
        val runCamera = call != null && call.camera && unlocked && previewTexture != null && cameraPermitted()
        if (runCamera && sender == null) {
            sender = CameraSender(app, group, ::sendFrame) { scope.launch { cameraStopped() } }.also {
                it.open(call.frontCamera)
                it.setPreview(previewTexture)
                it.setBitrate(bitrate)
            }
        } else if (!runCamera && sender != null) {
            sender?.close()
            sender = null
        }
        // In a group call the core sends video over the links that carry it, and nothing over others.
        val fast = call != null && (group || carriesVideo(call.contactId))
        val state = when {
            call == null || !call.camera -> VideoState.OFF
            runCamera && fast -> VideoState.ON
            else -> VideoState.PAUSED
        }
        val sending = call != null && state == VideoState.ON && call.phase == CallPhase.ACTIVE
        videoGroup = group
        videoMembers = if (group) call.participants else emptyList()
        videoContact = if (group) 0 else call?.contactId ?: 0
        videoStream = if (sending) call.id else null
        sender?.setSending(sending)
        if (call != null && state != announced) {
            announced = state
            perform { account -> account.setCamera(call.id, state) }
        }
        if (call == null) {
            announced = null
            askedForFastLink = false
        }
        val waits = call != null && !group && call.camera && !fast
        if (call != null && call.videoWaits != waits) _call.value = call.copy(videoWaits = waits)
        // Over Bluetooth video waits: the caller asks once to move the link to Wi-Fi, for its own
        // camera or the contact's (paused), so the two do not both open a hotspot.
        val wanted = call != null && !group && (call.camera || call.remoteVideo == VideoState.PAUSED)
        if (wanted && !fast && call.outgoing && call.phase == CallPhase.ACTIVE && unlocked && !askedForFastLink &&
            linkOf(call.contactId) != null
        ) {
            askedForFastLink = requestFastLink(call.contactId)
        }
        val show = call != null && !group && call.phase == CallPhase.ACTIVE && unlocked && remoteSurface != null
        if (show && receiver == null) {
            val id = call.id
            receiver = VideoReceiver(
                onNeedKeyFrame = { scope.launch { perform { account -> account.requestKeyFrame(id) } } },
                onFormat = { _remoteFormat.value = it },
            ).also { it.setSurface(remoteSurface) }
        } else if (!show && receiver != null) {
            receiver?.close()
            receiver = null
        }
        if (call == null) _remoteFormat.value = null
        // A group call: a decoder for each participant whose picture is shown.
        val groupCall = call?.takeIf { group && it.phase == CallPhase.ACTIVE && unlocked }
        val shown = groupCall?.let { c -> memberViews.keys.filter { it in c.participants }.toSet() }.orEmpty()
        for (member in memberReceivers.keys - shown) memberReceivers.remove(member)?.close()
        for (member in shown - memberReceivers.keys) {
            val id = groupCall?.id ?: break
            memberReceivers[member] = VideoReceiver(
                onNeedKeyFrame = { scope.launch { perform { account -> account.requestMemberKeyFrame(id, member) } } },
                onFormat = { format -> _memberFormats.update { it + (member to format) } },
            ).also { it.setSurface(memberViews[member]?.second) }
        }
        if (!group) _memberFormats.value = emptyMap()
    }

    /** The camera stopped by itself (another app took it, or it failed): it counts as turned off. */
    private fun cameraStopped() {
        sender?.close()
        sender = null
        _call.value?.takeIf { it.camera }?.let { _call.value = it.copy(camera = false) }
        updateVideo()
    }

    /**
     * An encoded frame from the camera thread. A link that cannot keep up shows as bytes waiting in
     * its queue, more than about a quarter second of video: then frames are skipped and the bitrate
     * comes down, so audio never waits behind seconds of video. Once the queue has drained, the
     * encoder is asked for a key frame and sending goes on with it (§8.6: frames are skipped only
     * before a key frame). The bitrate goes up again while the link keeps up.
     */
    private fun sendFrame(frame: ByteArray, key: Boolean, rotation: Int, width: Int, height: Int) {
        try {
            val stream = videoStream ?: return
            val (account, hub) = (account ?: return) to (hub ?: return)
            // In a group call, the slowest link to a participant sets the pace.
            val backlog = if (videoGroup) {
                videoMembers.mapNotNull { hub.backlog(it) }.maxOrNull() ?: 0L
            } else {
                hub.backlog(videoContact) ?: return
            }
            val now = SystemClock.elapsedRealtime()
            if (skipping) {
                if (backlog > DRAINED_BACKLOG) return
                if (!key) {
                    if (now - keyAskedAt > KEY_FRAME_AGAIN_MS) {
                        keyAskedAt = now
                        sender?.requestKeyFrame()
                    }
                    return
                }
                skipping = false
            } else if (backlog > maxOf(MIN_VIDEO_BACKLOG, bitrate / 8L * BACKLOG_MS / 1000)) {
                skipping = true
                keyAskedAt = 0
                slowDown(now)
                return
            }
            hub.perform { account.sendVideo(stream, key, rotation.toUByte(), width.toUShort(), height.toUShort(), frame) }
            if (now - slowedAt > RAISE_AFTER_MS && now - raisedAt > RAISE_EVERY_MS) {
                raisedAt = now
                sender?.let {
                    bitrate = (bitrate * 1.1).toInt().coerceAtMost(it.maxBitrateNow)
                    it.setBitrate(bitrate)
                }
            }
        } catch (e: CoreException) {
            if (BuildConfig.DEBUG) Log.d(TAG, "video frame not sent: $e")
        } finally {
            frame.fill(0)
        }
    }

    private fun slowDown(now: Long) {
        slowedAt = now
        val sender = sender ?: return
        bitrate = (bitrate * 0.7).toInt().coerceIn(CameraSender.MIN_BITRATE, sender.maxBitrateNow)
        sender.setBitrate(bitrate)
        if (BuildConfig.DEBUG) Log.d(TAG, "video: link falls behind, ${bitrate / 1000} kbit/s")
    }

    private fun perform(call: (Account) -> List<com.plyg.airchat.core.Action>) {
        val (account, hub) = (account ?: return) to (hub ?: return)
        try {
            hub.perform { call(account) }
        } catch (e: CoreException) {
            if (BuildConfig.DEBUG) Log.d(TAG, "video: $e")
        }
    }

    // Push-to-talk.

    fun startTalk(contactId: Long): Boolean = talk(contactId, null) { account -> account.startTalk(contactId) }

    /** Talks to the members of a group linked now. */
    fun startGroupTalk(groupId: Long): Boolean = talk(0, groupId) { account -> account.startGroupTalk(groupId) }

    /** Talks on the tuned walkie-talkie channel, to the members linked now. */
    fun startChannelTalk(channelId: Long): Boolean =
        talk(0, null, channelId) { account -> account.startChannelTalk() }

    private fun talk(contactId: Long, groupId: Long?, channelId: Long? = null, start: (Account) -> Started): Boolean {
        val (account, hub) = (account ?: return false) to (hub ?: return false)
        if (busy || !microphonePermitted()) return false
        val started = try {
            hub.performFor { start(account).let { it to it.actions } }
        } catch (e: CoreException) {
            if (BuildConfig.DEBUG) Log.w(TAG, "could not talk", e)
            null
        } ?: return false
        _talkRefused.value = null
        _talk.value = TalkUi(started.id, contactId, talking = true, groupId = groupId, channelId = channelId)
        // A channel's talk is only ever live; to a contact or a group it may become a message.
        recording = if (channelId == null) Recording() else null
        voiceOnly = false
        // Walkie-talkie style: out loud (or in the headset), opened with the chirp.
        startEngine(started.id, send = true, play = false, loud = true, chirp = true)
        return true
    }

    fun endTalk() {
        val talk = _talk.value?.takeIf { it.talking } ?: return
        if (talk.voiceMessage) return finishVoiceMessage(talk)
        val (account, hub) = (account ?: return) to (hub ?: return)
        try {
            hub.perform { account.endTalk(talk.id) }
        } catch (_: CoreException) {
        }
        endTalkLocally()
    }

    fun dismissTalkRefusal() {
        _talkRefused.value = null
    }

    fun onEvent(event: NetEvent) {
        when (event) {
            is NetEvent.CallRinging -> {
                endTalkLocally()
                _call.value = CallUi(
                    event.id,
                    event.contactId,
                    outgoing = false,
                    phase = CallPhase.RINGING_HERE,
                    video = event.video,
                    speaker = event.video,
                )
                ringer.start()
                notifications.incomingCall()
            }
            is NetEvent.CallReached -> ours(event.id)?.takeIf { it.phase == CallPhase.CALLING }?.let {
                _call.value = it.copy(phase = CallPhase.RINGING_THERE)
            }
            is NetEvent.CallAccepted -> ours(event.id)?.let {
                _call.value = it.copy(phase = CallPhase.ACTIVE, answeredAt = SystemClock.elapsedRealtime())
                startEngine(it.id, send = true, play = true, loud = it.video)
                if (it.speaker && !it.video) engine?.speaker = true
                updateVideo()
            }
            is NetEvent.VideoStateChanged -> ours(event.id)?.let {
                _call.value = if (it.groupId != null) {
                    it.copy(memberCameras = it.memberCameras + (event.from to event.state))
                } else {
                    it.copy(remoteVideo = event.state)
                }
                updateVideo()
            }
            is NetEvent.KeyFrameRequested -> if (ours(event.id) != null) sender?.requestKeyFrame()
            is NetEvent.LinkUp, is NetEvent.LinkDown -> updateVideo()
            is NetEvent.CallEnded -> ended(event.id, event.reason)
            is NetEvent.GroupCallRinging -> {
                endTalkLocally()
                _call.value = CallUi(
                    event.id,
                    event.contactId,
                    outgoing = false,
                    phase = CallPhase.RINGING_HERE,
                    groupId = event.groupId,
                    participants = listOf(event.contactId),
                )
                // A muted group's call rings silently: shown only if AirChat is open.
                if (account?.groupMuted(event.groupId) != true) {
                    ringer.start()
                    notifications.incomingCall()
                }
            }
            is NetEvent.GroupCallChanged -> ours(event.id)?.let {
                if (it.phase == CallPhase.CALLING && event.contactIds.isNotEmpty()) {
                    // The first member joined this device's call.
                    _call.value = it.copy(
                        phase = CallPhase.ACTIVE,
                        answeredAt = SystemClock.elapsedRealtime(),
                        participants = event.contactIds,
                    )
                    startEngine(it.id, send = true, play = true, loud = false)
                    if (it.speaker) engine?.speaker = true
                } else {
                    // Those gone take their cameras with them.
                    val cameras = it.memberCameras.filterKeys { member -> member in event.contactIds }
                    _call.value = it.copy(participants = event.contactIds, memberCameras = cameras)
                }
                updateVideo()
            }
            is NetEvent.TalkStarted -> {
                // Only while not in a call; the core turns talks down during one.
                _talk.value = TalkUi(event.id, event.contactId, talking = false)
                startEngine(event.id, send = false, play = true, loud = true, chirp = true)
            }
            is NetEvent.GroupTalkStarted -> {
                _talk.value = TalkUi(event.id, event.contactId, talking = false, groupId = event.groupId)
                startEngine(event.id, send = false, play = true, loud = true, chirp = true)
            }
            is NetEvent.ChannelTalkStarted -> {
                _talk.value = TalkUi(event.id, event.contactId, talking = false, channelId = event.channelId)
                startEngine(event.id, send = false, play = true, loud = true, chirp = true)
            }
            is NetEvent.TalkEnded -> {
                val talk = _talk.value?.takeIf { it.id contentEquals event.id } ?: return
                if (talk.talking && event.reason in VOICE_INSTEAD && recording != null) {
                    // Not taken live: the talk goes on as a voice message until the button is let go.
                    voiceOnly = true
                    _talk.value = TalkUi(talk.id, talk.contactId, talking = true, groupId = talk.groupId, voiceMessage = true)
                    return
                }
                if (talk.talking && event.reason != EndReason.HUNG_UP) {
                    _talkRefused.value = TalkRefusal(talk.contactId, event.reason, talk.groupId, talk.channelId)
                }
                endTalkLocally()
            }
            else -> Unit
        }
    }

    /** A packet of [from]'s audio; any thread. */
    fun onAudio(stream: ByteArray, from: Long, seq: UInt, packet: ByteArray) {
        val engine = engine
        if (engine != null && engineStream contentEquals stream) engine.push(from, seq, packet) else packet.fill(0)
    }

    /** The account closed: nothing can go on. */
    fun stopAll() {
        stopRinging()
        stopEngine()
        _call.value = null
        _talk.value = null
        updateVideo()
    }

    private fun ours(id: ByteArray) = _call.value?.takeIf { it.id contentEquals id }

    private fun ended(id: ByteArray, reason: EndReason) {
        val call = ours(id) ?: return
        stopRinging()
        stopEngine()
        _call.value = call.copy(phase = CallPhase.ENDED, ended = reason)
        updateVideo()
        scope.launch {
            delay(ENDED_SHOWN_MS)
            if (_call.value?.id contentEquals id) _call.value = null
        }
    }

    private fun endTalkLocally() {
        if (_talk.value == null) return
        _talk.value = null
        stopEngine()
        recording?.wipe()
        recording = null
        voiceOnly = false
    }

    /** The button was let go of a talk being recorded: the recording goes out as a voice message. */
    private fun finishVoiceMessage(talk: TalkUi) {
        val packets = recording?.take().orEmpty()
        endTalkLocally()
        if (packets.size < MIN_VOICE_PACKETS) return packets.forEach { it.fill(0) }
        val ogg = OggOpus.mux(packets, VOICE_RATE)
        val durationMs = OggOpus.durationMs(packets.size)
        packets.forEach { it.fill(0) }
        _voiceMessages.tryEmit(VoiceMessage(talk.contactId, talk.groupId, ogg, durationMs))
    }

    /** The microphone's next packet in a call or talk; on the capture thread. */
    private fun captured(stream: ByteArray, packet: ByteArray) {
        val recording = recording
        if (recording != null && !recording.add(packet) && voiceOnly) {
            // As long as a voice message may be: it goes now.
            scope.launch { _talk.value?.takeIf { it.voiceMessage }?.let(::finishVoiceMessage) }
        }
        if (!voiceOnly) sendAudio(stream, packet)
    }

    /** Packets kept in memory, up to what a voice message may hold. */
    private class Recording {
        private val packets = ArrayList<ByteArray>()
        private var bytes = 0L

        /** Keeps a copy of [packet]; false once the recording is full. */
        @Synchronized
        fun add(packet: ByteArray): Boolean {
            if (bytes + packet.size > LIMIT) return false
            packets += packet.copyOf()
            bytes += packet.size
            return true
        }

        @Synchronized
        fun take(): List<ByteArray> = packets.toList().also {
            packets.clear()
            bytes = 0
        }

        @Synchronized
        fun wipe() {
            packets.forEach { it.fill(0) }
            packets.clear()
            bytes = 0
        }

        private companion object {
            /** Room left for the Ogg pages around the packets (a few per cent). */
            val LIMIT = maxVoiceBytes().toLong() * 9 / 10
        }
    }

    private fun stopRinging() {
        ringer.stop()
        notifications.cancelCall()
    }

    private fun startEngine(stream: ByteArray, send: Boolean, play: Boolean, loud: Boolean, chirp: Boolean = false) {
        stopEngine()
        val engine = VoiceEngine(app) { packet -> captured(stream, packet) }
        engine.open(loud)
        if (play) engine.startPlaying(chirp) else if (chirp) engine.playChirp()
        if (send && microphonePermitted()) {
            onMicrophone(true)
            engine.startSending()
        }
        this.engine = engine
        engineStream = stream
    }

    private fun stopEngine() {
        val engine = engine ?: return
        this.engine = null
        engineStream = null
        onMicrophone(false)
        engine.close()
    }

    private fun sendAudio(stream: ByteArray, packet: ByteArray) {
        val (account, hub) = (account ?: return) to (hub ?: return)
        try {
            hub.perform { account.sendAudio(stream, packet) }
        } catch (_: CoreException) {
            // Locked or closed meanwhile; the call ends by itself.
        }
    }

    private companion object {
        const val TAG = "AirChat"
        const val ENDED_SHOWN_MS = 2_500L
        /** Talks that end like this go on as voice messages: not taken live now (muted, not
         * allowed), or busy in a call. */
        val VOICE_INSTEAD = setOf(EndReason.NOT_ALLOWED, EndReason.BUSY)
        /** A voice message shorter than half a second is not sent: a tap, not a message. */
        const val MIN_VOICE_PACKETS = 25
        /**
         * Video waiting on the link beyond which frames are skipped: this long at the bitrate, but
         * at least enough for a key frame; skipping goes on until the queue is down to
         * [DRAINED_BACKLOG].
         */
        const val BACKLOG_MS = 250L
        const val MIN_VIDEO_BACKLOG = 64 * 1024L
        const val DRAINED_BACKLOG = 16 * 1024L
        const val KEY_FRAME_AGAIN_MS = 1_000L
        /** The bitrate goes up again after this long without skipping, by a tenth this often. */
        const val RAISE_AFTER_MS = 4_000L
        const val RAISE_EVERY_MS = 2_000L
    }
}
