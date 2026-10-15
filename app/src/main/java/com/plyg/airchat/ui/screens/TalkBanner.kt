package com.plyg.airchat.ui.screens

import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.statusBars
import androidx.compose.foundation.layout.windowInsetsPadding
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.plyg.airchat.R

/**
 * Shown over every screen but the talker's conversation while push-to-talk audio plays, so the user
 * knows who is talking. [name] is null while AirChat is locked: then it names nobody.
 */
@Composable
fun TalkBanner(
    name: String?,
    onOpen: (() -> Unit)?,
    modifier: Modifier = Modifier,
    /** For a group talk: the group, named with the hint to open it. */
    groupName: String? = null,
    /** For a walkie-talkie channel's talk: the channel. */
    channelName: String? = null,
) {
    val pulse by rememberInfiniteTransition(label = "talk").animateFloat(
        initialValue = 1f,
        targetValue = 0.35f,
        animationSpec = infiniteRepeatable(tween(600), RepeatMode.Reverse),
        label = "pulse",
    )
    Surface(
        color = MaterialTheme.colorScheme.tertiary,
        contentColor = MaterialTheme.colorScheme.onTertiary,
        shape = RoundedCornerShape(bottomStart = 20.dp, bottomEnd = 20.dp),
        shadowElevation = 6.dp,
        modifier = modifier
            .fillMaxWidth()
            .let { if (onOpen != null) it.clickable(onClick = onOpen) else it },
    ) {
        Row(
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(12.dp),
            modifier = Modifier
                .windowInsetsPadding(WindowInsets.statusBars)
                .padding(horizontal = 16.dp, vertical = 12.dp),
        ) {
            Surface(shape = CircleShape, color = MaterialTheme.colorScheme.onTertiary.copy(alpha = 0.2f)) {
                Box(Modifier.size(40.dp), contentAlignment = Alignment.Center) {
                    Icon(painterResource(R.drawable.ic_mic), contentDescription = null, modifier = Modifier.alpha(pulse))
                }
            }
            Column(Modifier.weight(1f)) {
                Text(
                    if (name != null) stringResource(R.string.contact_talking, name) else stringResource(R.string.talk_banner_someone),
                    style = MaterialTheme.typography.titleMedium,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
                Text(
                    when {
                        groupName != null -> stringResource(R.string.talk_banner_group, groupName)
                        channelName != null -> stringResource(R.string.talk_banner_channel, channelName)
                        onOpen != null -> stringResource(R.string.talk_banner_open)
                        else -> stringResource(R.string.talk_banner_title)
                    },
                    style = MaterialTheme.typography.bodySmall,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
            }
        }
    }
}
