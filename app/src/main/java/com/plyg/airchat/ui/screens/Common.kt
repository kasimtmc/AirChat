package com.plyg.airchat.ui.screens

import androidx.annotation.DrawableRes
import androidx.annotation.StringRes
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.luminance
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.sp
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import com.plyg.airchat.R
import com.plyg.airchat.ui.theme.AvatarColors
import com.plyg.airchat.ui.theme.Teal
import java.time.Instant
import java.time.LocalDate
import java.time.ZoneId
import java.time.format.DateTimeFormatter
import java.time.format.FormatStyle

@Composable
fun ErrorText(@StringRes error: Int?) {
    if (error == null) return
    val text = if (error == R.string.error_pin_too_short) {
        stringResource(error, com.plyg.airchat.core.minPinLength().toInt())
    } else {
        stringResource(error)
    }
    Text(text, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodyMedium)
}

@Composable
fun BusyButton(@StringRes label: Int, busy: Boolean, onClick: () -> Unit, enabled: Boolean = true) {
    Button(onClick = onClick, enabled = enabled && !busy, modifier = Modifier.fillMaxWidth().height(52.dp)) {
        if (busy) {
            CircularProgressIndicator(Modifier.size(20.dp), strokeWidth = 2.dp)
        } else {
            Text(stringResource(label))
        }
    }
}

/**
 * The head of a screen that stands on its own (welcome, lock): [icon] in a round tint, a title
 * and, if given, what it is about.
 */
@Composable
fun ScreenHeader(@DrawableRes icon: Int, title: String, subtitle: String? = null) {
    Column(
        Modifier.fillMaxWidth(),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Box(
            Modifier.size(88.dp).clip(CircleShape).background(MaterialTheme.colorScheme.primaryContainer),
            contentAlignment = Alignment.Center,
        ) {
            Icon(
                painterResource(icon),
                contentDescription = null,
                tint = MaterialTheme.colorScheme.onPrimaryContainer,
                modifier = Modifier.size(44.dp),
            )
        }
        Text(title, style = MaterialTheme.typography.headlineSmall, textAlign = TextAlign.Center)
        if (subtitle != null) {
            Text(
                subtitle,
                style = MaterialTheme.typography.bodyLarge,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                textAlign = TextAlign.Center,
            )
        }
    }
}

/** A notice in a soft tint, with an icon: something to keep in mind. */
@Composable
fun NoticeCard(@DrawableRes icon: Int, text: String, warning: Boolean = false) {
    val (background, foreground) = if (warning) {
        MaterialTheme.colorScheme.errorContainer to MaterialTheme.colorScheme.onErrorContainer
    } else {
        MaterialTheme.colorScheme.secondaryContainer to MaterialTheme.colorScheme.onSecondaryContainer
    }
    Row(
        Modifier.fillMaxWidth().clip(RoundedCornerShape(16.dp)).background(background).padding(16.dp),
        horizontalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Icon(painterResource(icon), contentDescription = null, tint = foreground, modifier = Modifier.size(20.dp))
        Text(text, style = MaterialTheme.typography.bodyMedium, color = foreground)
    }
}

/** Whether something muted until [untilMs] (Unix ms) is muted now. */
fun isMuted(untilMs: Long): Boolean = System.currentTimeMillis() < untilMs

/** [name] with a mark when muted, for titles and lists. */
fun mutedName(name: String, untilMs: Long): String = if (isMuted(untilMs)) "$name 🔕" else name

/** "Muted", or until when, for a subtitle; null when not muted. */
@Composable
fun mutedText(untilMs: Long): String? = when {
    !isMuted(untilMs) -> null
    untilMs == Long.MAX_VALUE -> stringResource(R.string.muted_label)
    else -> stringResource(
        R.string.muted_until,
        Instant.ofEpochMilli(untilMs).atZone(ZoneId.systemDefault())
            .format(DateTimeFormatter.ofPattern("d MMM HH:mm")),
    )
}

/** Picks how long to mute something: [onMute] gets the time it ends (Unix ms; `Long.MAX_VALUE` for good). */
@Composable
fun MuteDialog(@StringRes explainer: Int, onDismiss: () -> Unit, onMute: (untilMs: Long) -> Unit) {
    val choices = listOf(
        R.string.mute_hour to 3_600_000L,
        R.string.mute_8_hours to 8 * 3_600_000L,
        R.string.mute_week to 7 * 24 * 3_600_000L,
        R.string.mute_always to 0L,
    )
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(stringResource(R.string.mute_for)) },
        text = {
            Column {
                Text(
                    stringResource(explainer),
                    style = MaterialTheme.typography.bodySmall,
                    modifier = Modifier.padding(bottom = 8.dp),
                )
                choices.forEach { (label, length) ->
                    TextButton(
                        onClick = {
                            onMute(if (length == 0L) Long.MAX_VALUE else System.currentTimeMillis() + length)
                        },
                        modifier = Modifier.fillMaxWidth(),
                    ) { Text(stringResource(label), modifier = Modifier.fillMaxWidth()) }
                }
            }
        },
        confirmButton = {},
        dismissButton = {
            TextButton(onClick = onDismiss) { Text(stringResource(R.string.cancel)) }
        },
    )
}

/** "Mute" or "Unmute" in a menu, by whether [mutedUntil] lies ahead. */
@Composable
fun MuteMenuItem(mutedUntil: Long, onMute: () -> Unit, onUnmute: () -> Unit) {
    val muted = isMuted(mutedUntil)
    DropdownMenuItem(
        text = {
            Column {
                Text(stringResource(if (muted) R.string.unmute else R.string.mute))
                mutedText(mutedUntil)?.let {
                    Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
            }
        },
        onClick = if (muted) onUnmute else onMute,
    )
}

/** A name's own pair of colors, the same wherever the name shows: its background and its foreground. */
@Composable
fun nameColors(name: String): Pair<Color, Color> {
    val (light, dark) = AvatarColors[(name.hashCode() and 0x7fffffff) % AvatarColors.size]
    val darkTheme = MaterialTheme.colorScheme.background.luminance() < 0.5f
    return if (darkTheme) dark to light else light to dark
}

/**
 * A person's or a group's round picture: their initial (a group's icon) on a color their name
 * picks, with a green dot while they are nearby.
 */
@Composable
fun Avatar(
    name: String,
    modifier: Modifier = Modifier,
    size: Dp = 48.dp,
    group: Boolean = false,
    nearby: Boolean = false,
) {
    val (background, foreground) = nameColors(name)
    Box(modifier.size(size)) {
        Box(
            Modifier.matchParentSize().clip(CircleShape).background(background),
            contentAlignment = Alignment.Center,
        ) {
            if (group) {
                Icon(
                    painterResource(R.drawable.ic_group),
                    contentDescription = null,
                    tint = foreground,
                    modifier = Modifier.size(size * 0.5f),
                )
            } else {
                Text(
                    name.trim().take(1).uppercase().ifEmpty { "?" },
                    color = foreground,
                    fontSize = (size.value * 0.42f).sp,
                    fontWeight = FontWeight.Medium,
                )
            }
        }
        if (nearby) {
            Box(
                Modifier
                    .align(Alignment.BottomEnd)
                    .size(size * 0.28f)
                    .clip(CircleShape)
                    .background(MaterialTheme.colorScheme.surface)
                    .padding(2.dp)
                    .clip(CircleShape)
                    .background(Teal),
            )
        }
    }
}

/** When something was written, as chat lists say it: a time today, "yesterday", a weekday, a date. */
@Composable
fun chatTime(atMs: Long): String {
    val zone = ZoneId.systemDefault()
    val time = Instant.ofEpochMilli(atMs).atZone(zone)
    val day = time.toLocalDate()
    val today = LocalDate.now(zone)
    return when {
        day == today -> time.format(DateTimeFormatter.ofPattern("HH:mm"))
        day == today.minusDays(1) -> stringResource(R.string.yesterday)
        day.isAfter(today.minusDays(7)) -> time.format(DateTimeFormatter.ofPattern("EEE"))
        else -> time.format(DateTimeFormatter.ofLocalizedDate(FormatStyle.SHORT))
    }
}

/** A day in a conversation: "today", "yesterday", or its date. */
@Composable
fun dayLabel(atMs: Long): String {
    val zone = ZoneId.systemDefault()
    val day = Instant.ofEpochMilli(atMs).atZone(zone).toLocalDate()
    val today = LocalDate.now(zone)
    return when (day) {
        today -> stringResource(R.string.today)
        today.minusDays(1) -> stringResource(R.string.yesterday)
        else -> day.format(DateTimeFormatter.ofLocalizedDate(FormatStyle.LONG))
    }
}
