package com.plyg.airchat.ui.screens

import androidx.compose.foundation.combinedClickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyListState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.input.TextFieldLineLimits
import androidx.compose.foundation.text.input.TextFieldState
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.FilledIconButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LocalContentColor
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextField
import androidx.compose.material3.TextFieldDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Shape
import androidx.compose.ui.graphics.luminance
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.plyg.airchat.R
import kotlinx.coroutines.delay
import com.plyg.airchat.ui.VoicePlayback
import com.plyg.airchat.core.voiceMime
import com.plyg.airchat.core.voiceKeepMs
import com.plyg.airchat.core.maxVoiceBytes
import com.plyg.airchat.core.AttachmentState
import com.plyg.airchat.core.Attachment
import androidx.compose.runtime.mutableLongStateOf
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.CircularProgressIndicator
import java.time.Instant
import java.time.ZoneId
import java.time.format.DateTimeFormatter

private val timeFormat = DateTimeFormatter.ofPattern("HH:mm")

/** Whether the theme is dark: chat colors differ a little. */
@Composable
private fun dark() = MaterialTheme.colorScheme.background.luminance() < 0.5f

/** Behind the messages: a shade apart from the bubbles. */
@Composable
fun chatBackground(): Color = if (dark()) MaterialTheme.colorScheme.surface else MaterialTheme.colorScheme.surfaceContainer

/** A bubble's color: the user's own in the brand's light tint, others' plain. */
@Composable
fun bubbleColor(outgoing: Boolean): Color = when {
    outgoing -> MaterialTheme.colorScheme.primaryContainer
    dark() -> MaterialTheme.colorScheme.surfaceContainerHighest
    else -> MaterialTheme.colorScheme.surfaceContainerLowest
}

/** A bubble's shape: round, with a small corner where the last of a run points at its sender. */
fun bubbleShape(outgoing: Boolean, tail: Boolean): Shape {
    val small = if (tail) 4.dp else 18.dp
    return if (outgoing) {
        RoundedCornerShape(topStart = 18.dp, topEnd = 18.dp, bottomEnd = small, bottomStart = 18.dp)
    } else {
        RoundedCornerShape(topStart = 18.dp, topEnd = 18.dp, bottomEnd = 18.dp, bottomStart = small)
    }
}

/**
 * The top bar's title of a conversation: the picture, the name ([title] if it says more, such as
 * that it is muted), and how they are reached.
 */
@Composable
fun ConversationTitle(
    name: String,
    status: String,
    statusActive: Boolean,
    modifier: Modifier = Modifier,
    title: String = name,
    group: Boolean = false,
    nearby: Boolean = false,
    /** The contact's build was attested as the official one on a verified phone (§6.10). */
    verified: Boolean = false,
) {
    Row(modifier, verticalAlignment = Alignment.CenterVertically) {
        Avatar(name, size = 40.dp, group = group, nearby = nearby)
        Spacer(Modifier.width(12.dp))
        Column {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(
                    title,
                    style = MaterialTheme.typography.titleMedium,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                    modifier = Modifier.weight(1f, fill = false),
                )
                if (verified) {
                    Spacer(Modifier.width(4.dp))
                    Icon(
                        painterResource(R.drawable.ic_verified),
                        contentDescription = stringResource(R.string.verified_build),
                        tint = MaterialTheme.colorScheme.primary,
                        modifier = Modifier.size(18.dp),
                    )
                }
            }
            Text(
                status,
                style = MaterialTheme.typography.bodySmall,
                color = if (statusActive) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurfaceVariant,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
        }
    }
}

/**
 * A conversation's messages, the newest at the bottom, each day's under its date. [bubble] draws a
 * message; `first` says whether it begins a run of one sender's messages, `last` whether it ends it.
 */
@Composable
fun <T> MessageList(
    messages: List<T>,
    key: (T) -> Any,
    at: (T) -> Long,
    from: (T) -> Any,
    listState: LazyListState,
    empty: String,
    modifier: Modifier = Modifier,
    bubble: @Composable (message: T, first: Boolean, last: Boolean) -> Unit,
) {
    Box(modifier) {
        if (messages.isEmpty()) {
            Column(
                Modifier.align(Alignment.Center).padding(32.dp),
                horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                Icon(
                    painterResource(R.drawable.ic_lock),
                    contentDescription = null,
                    tint = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.size(32.dp),
                )
                Text(
                    empty,
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    textAlign = TextAlign.Center,
                )
            }
        }
        LazyColumn(
            state = listState,
            modifier = Modifier.fillMaxSize(),
            reverseLayout = true,
            contentPadding = PaddingValues(horizontal = 10.dp, vertical = 8.dp),
        ) {
            // Newest first, as the list is laid out from the bottom.
            val reversed = messages.asReversed()
            reversed.forEachIndexed { index, message ->
                val newer = reversed.getOrNull(index - 1)
                val older = reversed.getOrNull(index + 1)
                val dayStarts = older == null || !sameDay(at(older), at(message))
                val first = dayStarts || from(older!!) != from(message)
                val last = newer == null || !sameDay(at(message), at(newer)) || from(newer) != from(message)
                item(key = key(message)) {
                    Box(Modifier.padding(top = if (first) 8.dp else 2.dp)) { bubble(message, first, last) }
                }
                if (dayStarts) item(key = "day-${key(message)}") { DaySeparator(at(message)) }
            }
        }
    }
}

private fun sameDay(a: Long, b: Long): Boolean {
    val zone = ZoneId.systemDefault()
    return Instant.ofEpochMilli(a).atZone(zone).toLocalDate() == Instant.ofEpochMilli(b).atZone(zone).toLocalDate()
}

@Composable
private fun DaySeparator(atMs: Long) {
    Box(Modifier.fillMaxWidth().padding(vertical = 8.dp), contentAlignment = Alignment.Center) {
        Surface(color = MaterialTheme.colorScheme.secondaryContainer, shape = RoundedCornerShape(8.dp)) {
            Text(
                dayLabel(atMs),
                style = MaterialTheme.typography.labelMedium,
                color = MaterialTheme.colorScheme.onSecondaryContainer,
                modifier = Modifier.padding(horizontal = 10.dp, vertical = 3.dp),
            )
        }
    }
}

/**
 * A message's bubble, on the right when it is the user's own: [content], then the time it was
 * written and its [status]. [tail] points the last of a run at its sender. With [longPressMenu], a
 * long press opens a menu of it; its items get a way to close the menu.
 */
@Composable
fun Bubble(
    outgoing: Boolean,
    tail: Boolean,
    atMs: Long,
    status: @Composable () -> Unit = {},
    longPressMenu: (@Composable ColumnScope.(close: () -> Unit) -> Unit)? = null,
    content: @Composable ColumnScope.() -> Unit,
) {
    var menu by remember { mutableStateOf(false) }
    Row(Modifier.fillMaxWidth(), horizontalArrangement = if (outgoing) Arrangement.End else Arrangement.Start) {
        Box {
            Surface(
                shape = bubbleShape(outgoing, tail),
                color = bubbleColor(outgoing),
                shadowElevation = 1.dp,
                modifier = Modifier
                    .widthIn(max = 300.dp)
                    .let { if (longPressMenu != null) it.combinedClickable(onClick = {}, onLongClick = { menu = true }) else it },
            ) {
                Column(Modifier.padding(start = 12.dp, end = 10.dp, top = 6.dp, bottom = 4.dp)) {
                    content()
                    Row(
                        Modifier.align(Alignment.End),
                        horizontalArrangement = Arrangement.spacedBy(4.dp),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        val time = Instant.ofEpochMilli(atMs).atZone(ZoneId.systemDefault()).format(timeFormat)
                        Text(time, style = MaterialTheme.typography.labelSmall, color = LocalContentColor.current.copy(alpha = 0.6f))
                        status()
                    }
                }
            }
            if (longPressMenu != null) {
                DropdownMenu(expanded = menu, onDismissRequest = { menu = false }) { longPressMenu { menu = false } }
            }
        }
    }
}

/** A message's state after its time: [mark], in words when it went wrong ([problem]) or for screen readers. */
@Composable
fun StatusText(mark: String, label: String, problem: Boolean = false, done: Boolean = false) {
    Text(
        if (problem) "$mark $label" else mark,
        style = MaterialTheme.typography.labelSmall,
        color = when {
            problem -> MaterialTheme.colorScheme.error
            done -> MaterialTheme.colorScheme.primary
            else -> LocalContentColor.current.copy(alpha = 0.6f)
        },
        modifier = Modifier.semantics { contentDescription = label },
    )
}

/**
 * The message field, round, with attaching inside it, and beside it the send button, or while the
 * field is empty the push-to-talk button if [talk] gives one.
 */
@Composable
fun MessageInput(
    input: TextFieldState,
    onSend: () -> Unit,
    onPickMedia: () -> Unit,
    onPickFile: () -> Unit,
    talk: (@Composable () -> Unit)?,
) {
    var attachMenu by remember { mutableStateOf(false) }
    Row(
        Modifier.fillMaxWidth().padding(start = 8.dp, end = 8.dp, top = 4.dp, bottom = 8.dp),
        verticalAlignment = Alignment.Bottom,
    ) {
        Surface(
            shape = RoundedCornerShape(24.dp),
            color = bubbleColor(outgoing = false),
            modifier = Modifier.weight(1f),
        ) {
            Row(verticalAlignment = Alignment.Bottom) {
                Box {
                    IconButton(onClick = { attachMenu = true }) {
                        Icon(
                            painterResource(R.drawable.ic_attach),
                            contentDescription = stringResource(R.string.attach),
                            tint = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                    DropdownMenu(expanded = attachMenu, onDismissRequest = { attachMenu = false }) {
                        DropdownMenuItem(
                            text = { Text(stringResource(R.string.attach_media)) },
                            onClick = {
                                attachMenu = false
                                onPickMedia()
                            },
                        )
                        DropdownMenuItem(
                            text = { Text(stringResource(R.string.attach_file)) },
                            onClick = {
                                attachMenu = false
                                onPickFile()
                            },
                        )
                    }
                }
                TextField(
                    state = input,
                    placeholder = { Text(stringResource(R.string.message_hint)) },
                    lineLimits = TextFieldLineLimits.MultiLine(maxHeightInLines = 5),
                    colors = TextFieldDefaults.colors(
                        focusedContainerColor = Color.Transparent,
                        unfocusedContainerColor = Color.Transparent,
                        focusedIndicatorColor = Color.Transparent,
                        unfocusedIndicatorColor = Color.Transparent,
                    ),
                    modifier = Modifier.weight(1f),
                )
            }
        }
        Spacer(Modifier.width(6.dp))
        if (input.text.isBlank() && talk != null) {
            talk()
        } else {
            FilledIconButton(onClick = onSend, enabled = input.text.isNotBlank(), modifier = Modifier.size(52.dp)) {
                Icon(painterResource(R.drawable.ic_send), contentDescription = stringResource(R.string.send))
            }
        }
    }
}

/** Whether [attachment] is a voice message: the core's rule (rust/airchat-protocol/docs/protocol.md §8.4). */
fun isVoice(attachment: Attachment): Boolean = attachment.mime == voiceMime() && attachment.size <= maxVoiceBytes()

/**
 * A voice message in a bubble: play or pause, how far it is and how long, and once one that came in
 * was played, how long it stays.
 */
@Composable
fun VoiceContent(attachment: Attachment, outgoing: Boolean, playback: VoicePlayback?, onToggle: () -> Unit) {
    val complete = attachment.state == AttachmentState.COMPLETE
    Row(
        Modifier.widthIn(min = 220.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(10.dp),
    ) {
        when {
            complete -> FilledIconButton(onClick = onToggle, modifier = Modifier.size(40.dp)) {
                Icon(
                    painterResource(if (playback?.playing == true) R.drawable.ic_pause else R.drawable.ic_play),
                    contentDescription = stringResource(if (playback?.playing == true) R.string.voice_pause else R.string.voice_play),
                )
            }
            attachment.state == AttachmentState.DOWNLOADING || attachment.state == AttachmentState.OFFERED ->
                Box(Modifier.size(40.dp), contentAlignment = Alignment.Center) {
                    CircularProgressIndicator(Modifier.size(22.dp), strokeWidth = 2.dp)
                }
            else -> Box(Modifier.size(40.dp), contentAlignment = Alignment.Center) {
                Icon(painterResource(R.drawable.ic_mic), contentDescription = null, tint = LocalContentColor.current.copy(alpha = 0.5f))
            }
        }
        Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            if (complete) {
                val duration = playback?.durationMs?.takeIf { it > 0 } ?: estimatedVoiceMs(attachment.size.toLong())
                LinearProgressIndicator(
                    progress = { if (playback != null && duration > 0) (playback.positionMs.toFloat() / duration).coerceIn(0f, 1f) else 0f },
                    modifier = Modifier.fillMaxWidth(),
                )
                Text(
                    voiceTime(if (playback != null && playback.positionMs > 0) playback.positionMs else duration),
                    style = MaterialTheme.typography.labelSmall,
                    color = LocalContentColor.current.copy(alpha = 0.7f),
                )
            } else {
                Text(
                    stringResource(
                        when {
                            attachment.state == AttachmentState.GONE && attachment.playedAtMs > 0 -> R.string.voice_expired
                            attachment.state == AttachmentState.GONE -> R.string.file_gone
                            else -> R.string.voice_message
                        },
                    ),
                    style = MaterialTheme.typography.bodyMedium,
                )
            }
            if (!outgoing && complete && attachment.playedAtMs > 0) {
                var now by remember { mutableLongStateOf(System.currentTimeMillis()) }
                LaunchedEffect(attachment.playedAtMs) {
                    while (true) {
                        now = System.currentTimeMillis()
                        delay(30_000)
                    }
                }
                val left = (attachment.playedAtMs + voiceKeepMs() - now).coerceAtLeast(0)
                Text(
                    stringResource(R.string.voice_deleted_in, ((left + 59_999) / 60_000).toInt()),
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.error,
                )
            }
        }
    }
}

/** How long a voice message of [bytes] plays, before the player says: Opus at 24 kbit/s in Ogg. */
private fun estimatedVoiceMs(bytes: Long): Long = bytes * 1000 / 3125

private fun voiceTime(ms: Long): String {
    val seconds = ms / 1000
    return "%d:%02d".format(seconds / 60, seconds % 60)
}
