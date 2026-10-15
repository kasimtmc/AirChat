package com.plyg.airchat.net

import android.os.SystemClock
import com.plyg.airchat.core.Account
import com.plyg.airchat.core.Action
import com.plyg.airchat.core.Contact
import com.plyg.airchat.core.ContactRequest
import com.plyg.airchat.core.EndReason
import com.plyg.airchat.core.Failure
import com.plyg.airchat.core.Group
import com.plyg.airchat.core.GroupMessage
import com.plyg.airchat.core.HotspotOffer
import com.plyg.airchat.core.MemberProposal
import com.plyg.airchat.core.Message
import com.plyg.airchat.core.MoveTarget
import com.plyg.airchat.core.PathClass
import com.plyg.airchat.core.VideoState
import com.plyg.airchat.core.pathConnectionBase
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.SharedFlow
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicLong

/** What the app hears about connections. */
sealed interface NetEvent {
    data class ShowSas(val connection: Long, val emoji: List<String>) : NetEvent
    data class Paired(val connection: Long, val contact: Contact) : NetEvent
    /** Someone who typed this device's AirChat ID asks to be added (rust/airchat-protocol/docs/protocol.md §4.8). */
    data class ContactRequested(val connection: Long, val request: ContactRequest) : NetEvent
    /** A contact proposes a group of the two of you and someone else (rust/airchat-protocol/docs/protocol.md §9.8). */
    data class MemberProposed(val contactId: Long, val proposal: MemberProposal) : NetEvent
    /** The contact did not agree to the group this device proposed. */
    data class MemberProposalDeclined(val contactId: Long) : NetEvent
    data class Failed(val connection: Long, val reason: Failure) : NetEvent
    data class LinkUp(val contactId: Long, val via: TransportKind) : NetEvent
    data class LinkDown(val contactId: Long) : NetEvent
    data class MessageReceived(val message: Message) : NetEvent
    /** A message arrived while locked; it waits, encrypted, until the next unlock. */
    data class MessageArrived(val contactId: Long) : NetEvent
    /** Something waits to be sent to a contact linked over Bluetooth only: offer to move to Wi-Fi. */
    data class WaitingForWifi(val contactId: Long) : NetEvent
    /** The contact asks this device to open a hotspot so the link can move there (§8.3). */
    data class MoveRequested(val contactId: Long, val target: MoveTarget) : NetEvent
    data class HotspotOffered(val contactId: Long, val offer: HotspotOffer) : NetEvent
    data class MoveDeclined(val contactId: Long, val target: MoveTarget) : NetEvent
    data class MessageUpdated(val message: Message) : NetEvent
    /** No path through Air Providers to the contact that carries [pathClass] was found (rust/airchat-protocol/docs/protocol.md §12.2). */
    data class PathFailed(val contactId: Long, val pathClass: PathClass) : NetEvent
    /** A contact calls (rust/airchat-protocol/docs/protocol.md §8.5), maybe as a video call (§8.6). */
    class CallRinging(val id: ByteArray, val contactId: Long, val video: Boolean) : NetEvent
    /** This device's call rings on the contact's device. */
    class CallReached(val id: ByteArray) : NetEvent
    class CallAccepted(val id: ByteArray) : NetEvent
    class CallEnded(val id: ByteArray, val reason: EndReason) : NetEvent
    /** The contact's camera in the call went on, off or paused. */
    /** The camera of [from] (the contact, or a group call's participant) went on, off or paused. */
    class VideoStateChanged(val id: ByteArray, val from: Long, val state: VideoState) : NetEvent
    /** The contact cannot decode this device's video: the next frame should be a key frame. */
    class KeyFrameRequested(val id: ByteArray) : NetEvent
    /** A contact talks (push-to-talk). */
    class TalkStarted(val id: ByteArray, val contactId: Long) : NetEvent
    class TalkEnded(val id: ByteArray, val reason: EndReason) : NetEvent
    /** A member talks to a group (push-to-talk); [contactId] is its row, contact or not. */
    class GroupTalkStarted(val id: ByteArray, val groupId: Long, val contactId: Long) : NetEvent
    /** A member calls a group. */
    class GroupCallRinging(val id: ByteArray, val groupId: Long, val contactId: Long) : NetEvent
    /** Who else is in the group call this device is in. */
    class GroupCallChanged(val id: ByteArray, val contactIds: List<Long>) : NetEvent
    /** A member of the tuned walkie-talkie channel talks; [contactId] names it in `channelPeers`. */
    class ChannelTalkStarted(val id: ByteArray, val channelId: Long, val contactId: Long) : NetEvent
    /** Members of the tuned channel came or went. */
    data object ChannelPeersChanged : NetEvent
    /** Whether a contact's build is verified changed. */
    data class AttestationChanged(val contactId: Long) : NetEvent
    /** A group was created or changed members, or this device left it or was removed. */
    data class GroupChanged(val group: Group) : NetEvent
    data class GroupMessageReceived(val message: GroupMessage) : NetEvent
    /** A group message arrived while locked; it waits, encrypted, until the next unlock. */
    data class GroupMessageArrived(val groupId: Long?) : NetEvent
    /** An outgoing group message reached a member. */
    data class GroupMessageUpdated(val message: GroupMessage) : NetEvent
}

/**
 * Connects transports to the Rust core: every received frame goes to [Account.onFrame], and the
 * returned actions are carried out here. Transport-independent; LAN is the first user.
 */
class ConnectionHub(
    private val account: Account,
    private val scope: CoroutineScope,
    /** Called on an I/O thread after a connection closed and the core heard about it. */
    private val onClosed: (TransportKind) -> Unit = {},
    /** Each packet of incoming audio, straight from the thread that received it: not through
     * [events], which may drop under load. */
    private val onAudio: (stream: ByteArray, from: Long, seq: UInt, packet: ByteArray) -> Unit = { _, _, _, _ -> },
    /** Each frame of incoming video, like [onAudio]. */
    private val onVideo: (VideoFrame) -> Unit = {},
    /** The attested key is to sign [message] for the link to a contact (rust/airchat-protocol/docs/protocol.md §6.10). */
    private val onAttestationWanted: (contactId: Long, message: ByteArray) -> Unit = { _, _ -> },
) {
    private val connections = ConcurrentHashMap<Long, FramedConnection>()
    /** The connection each linked contact's link runs on. */
    private val links = ConcurrentHashMap<Long, Long>()
    private val nextId = AtomicLong(1)
    /** Core call and queuing of its frames happen together, so frames keep the core's order. */
    private val lock = Any()
    /** Set under [lock] before the account is closed; no core call may follow. */
    private var closed = false

    private val _events = MutableSharedFlow<NetEvent>(extraBufferCapacity = 64)
    val events: SharedFlow<NetEvent> = _events

    /** Starts carrying frames on a connected stream (incoming or outgoing) and returns its id. */
    fun attach(stream: StreamChannel, kind: TransportKind): Long {
        val connection = FramedConnection(nextId.getAndIncrement(), kind, stream)
        connections[connection.id] = connection
        // Bluetooth carries discovery and setting up Wi-Fi only (rust/airchat-protocol/docs/protocol.md §7.3).
        if (kind == TransportKind.BLE) synchronized(lock) { if (!closed) account.markSetupOnly(connection.id.toULong()) }
        connection.start(
            scope,
            onFrame = { frame -> perform { account.onFrame(connection.id.toULong(), frame) } },
            onClosed = {
                connections.remove(connection.id)
                perform { account.connectionClosed(connection.id.toULong()) }
                onClosed(kind)
            },
        )
        return connection.id
    }

    /** Runs a core call that returns actions, and carries them out. */
    fun perform(call: () -> List<Action>) {
        performFor { Unit to call() }
    }

    /** Like [perform] for calls that also return a result; `null` once the hub is closed. */
    fun <T> performFor(call: () -> Pair<T, List<Action>>): T? {
        val (result, actions) = synchronized(lock) {
            if (closed) return null
            call().also { (_, actions) ->
                for (action in actions) {
                    when (action) {
                        is Action.Send -> connections[action.connection.toLong()]?.send(action.bytes)
                        is Action.Close -> connections[action.connection.toLong()]?.closeAfterSending()
                        else -> Unit
                    }
                }
            }
        }
        for (action in actions) {
            when (action) {
                is Action.ShowSas -> _events.tryEmit(NetEvent.ShowSas(action.connection.toLong(), action.emoji))
                is Action.Paired -> _events.tryEmit(NetEvent.Paired(action.connection.toLong(), action.contact))
                is Action.ContactRequest ->
                    _events.tryEmit(NetEvent.ContactRequested(action.connection.toLong(), action.request))
                is Action.MemberProposed -> _events.tryEmit(NetEvent.MemberProposed(action.contactId, action.proposal))
                is Action.MemberProposalDeclined -> _events.tryEmit(NetEvent.MemberProposalDeclined(action.contactId))
                is Action.Failed -> _events.tryEmit(NetEvent.Failed(action.connection.toLong(), action.reason))
                is Action.LinkUp -> {
                    val via = kindOf(action.connection.toLong()) ?: continue
                    links[action.contactId] = action.connection.toLong()
                    _events.tryEmit(NetEvent.LinkUp(action.contactId, via))
                }
                is Action.LinkDown -> {
                    links.remove(action.contactId)
                    _events.tryEmit(NetEvent.LinkDown(action.contactId))
                }
                is Action.MessageReceived -> _events.tryEmit(NetEvent.MessageReceived(action.message))
                is Action.MessageUpdated -> _events.tryEmit(NetEvent.MessageUpdated(action.message))
                is Action.MessageArrived -> _events.tryEmit(NetEvent.MessageArrived(action.contactId))
                is Action.WaitingForWifi -> _events.tryEmit(NetEvent.WaitingForWifi(action.contactId))
                is Action.MoveRequested -> _events.tryEmit(NetEvent.MoveRequested(action.contactId, action.target))
                is Action.HotspotOffered -> _events.tryEmit(NetEvent.HotspotOffered(action.contactId, action.offer))
                is Action.MoveDeclined -> _events.tryEmit(NetEvent.MoveDeclined(action.contactId, action.target))
                is Action.CallRinging -> _events.tryEmit(NetEvent.CallRinging(action.id, action.contactId, action.video))
                is Action.CallReached -> _events.tryEmit(NetEvent.CallReached(action.id))
                is Action.CallAccepted -> _events.tryEmit(NetEvent.CallAccepted(action.id))
                is Action.CallEnded -> _events.tryEmit(NetEvent.CallEnded(action.id, action.reason))
                is Action.TalkStarted -> _events.tryEmit(NetEvent.TalkStarted(action.id, action.contactId))
                is Action.TalkEnded -> _events.tryEmit(NetEvent.TalkEnded(action.id, action.reason))
                is Action.Audio -> onAudio(action.stream, action.from, action.seq, action.packet)
                is Action.GroupTalkStarted ->
                    _events.tryEmit(NetEvent.GroupTalkStarted(action.id, action.groupId, action.contactId))
                is Action.GroupCallRinging ->
                    _events.tryEmit(NetEvent.GroupCallRinging(action.id, action.groupId, action.contactId))
                is Action.GroupCallChanged -> _events.tryEmit(NetEvent.GroupCallChanged(action.id, action.contactIds))
                is Action.ChannelTalkStarted ->
                    _events.tryEmit(NetEvent.ChannelTalkStarted(action.id, action.channelId, action.contactId))
                is Action.ChannelPeersChanged -> _events.tryEmit(NetEvent.ChannelPeersChanged)
                is Action.AttestationWanted -> onAttestationWanted(action.contactId, action.message)
                is Action.AttestationChanged -> _events.tryEmit(NetEvent.AttestationChanged(action.contactId))
                is Action.GroupChanged -> _events.tryEmit(NetEvent.GroupChanged(action.group))
                is Action.GroupMessageReceived -> _events.tryEmit(NetEvent.GroupMessageReceived(action.message))
                is Action.GroupMessageArrived -> _events.tryEmit(NetEvent.GroupMessageArrived(action.groupId))
                is Action.GroupMessageUpdated -> _events.tryEmit(NetEvent.GroupMessageUpdated(action.message))
                is Action.PathFailed -> _events.tryEmit(NetEvent.PathFailed(action.contactId, action.pathClass))
                is Action.VideoStateChanged -> _events.tryEmit(NetEvent.VideoStateChanged(action.id, action.from, action.state))
                is Action.KeyFrameRequested -> _events.tryEmit(NetEvent.KeyFrameRequested(action.id))
                is Action.Video -> onVideo(
                    VideoFrame(
                        action.stream,
                        action.from,
                        action.key,
                        action.rotation.toInt(),
                        action.width.toInt(),
                        action.height.toInt(),
                        action.frame,
                    ),
                )
                is Action.Send, is Action.Close -> Unit
            }
        }
        return result
    }

    /**
     * Bytes queued on the link to a contact and not yet written; null without a link. Over a path
     * through Air Providers, the bytes the other end has not taken yet.
     */
    fun backlog(contactId: Long): Long? {
        val connection = links[contactId] ?: return null
        if (connection < PATH_BASE) return connections[connection]?.backlog
        return synchronized(lock) { if (closed) null else account.pathBacklog(connection.toULong())?.toLong() }
    }

    /** What carries `connection`, while it is open. The core carries links over paths itself. */
    fun kindOf(connection: Long): TransportKind? =
        if (connection >= PATH_BASE) TransportKind.RELAY else connections[connection]?.kind

    /**
     * Whether the link to a contact carried a large frame (a file's chunk, video) in the last
     * [withinMs]: it is busy with more than messages.
     */
    fun carriedBulk(contactId: Long, withinMs: Long): Boolean {
        val connection = connections[links[contactId] ?: return false] ?: return false
        return connection.bulkAt != 0L && SystemClock.elapsedRealtime() - connection.bulkAt < withinMs
    }

    /** Whether any open connection runs over `kind`. */
    fun carries(kind: TransportKind): Boolean = connections.values.any { it.kind == kind }

    /** Closes the connections a transport carries, e.g. when that transport stops. */
    fun closeConnections(kind: TransportKind) {
        connections.values.filter { it.kind == kind }.forEach { it.closeAfterSending() }
    }

    /** Closes every connection. Afterwards the account may be closed: nothing here calls it again. */
    fun closeAll() {
        synchronized(lock) { closed = true }
        connections.values.forEach { it.closeAfterSending() }
    }
}

/** Links over paths through Air Providers run on connection ids from here up; the platform's stay below. */
private val PATH_BASE = pathConnectionBase().toLong()

/** A frame of video, put back together by the core (rust/airchat-protocol/docs/protocol.md §8.6, §9.9). */
class VideoFrame(
    val stream: ByteArray,
    /** Whose: the contact, or a group call's participant (by row). */
    val from: Long,
    val key: Boolean,
    /** Quarter turns clockwise that show it upright. */
    val rotation: Int,
    val width: Int,
    val height: Int,
    /** H.264, Annex B. */
    val data: ByteArray,
)
