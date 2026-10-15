package com.plyg.airchat.ui.screens

import android.content.pm.ActivityInfo
import android.graphics.SurfaceTexture
import android.os.SystemClock
import android.text.format.DateUtils
import android.view.TextureView
import androidx.activity.compose.BackHandler
import androidx.activity.compose.LocalActivity
import androidx.annotation.DrawableRes
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.FilledIconButton
import androidx.compose.material3.FilledTonalIconToggleButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButtonDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.key
import androidx.compose.runtime.mutableLongStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberUpdatedState
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.viewinterop.AndroidView
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.material3.LocalContentColor
import com.plyg.airchat.R
import com.plyg.airchat.core.EndReason
import com.plyg.airchat.core.VideoState
import com.plyg.airchat.runtime.CallPhase
import com.plyg.airchat.runtime.CallUi
import com.plyg.airchat.video.VideoFormat
import com.plyg.airchat.video.VideoTextureView
import kotlinx.coroutines.delay

private val Answer = Color(0xFF1D9E75)
private val HangUp = Color(0xFFE5484D)
/** A voice call is dark whatever the theme, as calls are in messaging apps: deep sky to night. */
private val CallTop = Color(0xFF0E3A52)
private val CallBottom = Color(0xFF0B1116)
private val CallAccent = Color(0xFF84CFFF)

/**
 * A call, full screen and over everything else. [name] is null while AirChat is locked: who calls
 * shows only after unlocking, and so does video.
 */
@Composable
fun CallScreen(
    call: CallUi,
    name: String?,
    /** For a group call: who calls, or who is in it. */
    detail: String? = null,
    unlocked: Boolean = name != null,
    /** The contact's picture as it arrives. */
    remoteFormat: VideoFormat? = null,
    onAnswer: () -> Unit,
    onHangUp: () -> Unit,
    onMute: (Boolean) -> Unit,
    onSpeaker: (Boolean) -> Unit,
    onCamera: (Boolean) -> Unit = {},
    onSwitchCamera: () -> Unit = {},
    /** The views' textures while shown, null when they go; their owner releases them. */
    onLocalPreview: (SurfaceTexture?) -> Unit = {},
    onRemoteView: (SurfaceTexture?) -> Unit = {},
    /** For a group's admin in its call: adds people, since nothing else shows during a call. */
    onAddPeople: (() -> Unit)? = null,
    /** In a group call: each participant's picture as it arrives, their names, and their views. */
    memberFormats: Map<Long, VideoFormat> = emptyMap(),
    memberNames: Map<Long, String> = emptyMap(),
    onMemberView: (Long, SurfaceTexture?) -> Unit = { _, _ -> },
) {
    // Back does not end a call; the buttons do.
    BackHandler {}
    val oneToOne = call.groupId == null
    val video = oneToOne && (call.video || call.camera || call.remoteVideo != VideoState.OFF)
    var now by remember { mutableLongStateOf(SystemClock.elapsedRealtime()) }
    LaunchedEffect(call.answeredAt) {
        while (call.answeredAt != null) {
            now = SystemClock.elapsedRealtime()
            delay(1_000)
        }
    }
    val status = when (call.phase) {
        CallPhase.CALLING -> stringResource(R.string.call_calling)
        CallPhase.RINGING_THERE -> stringResource(R.string.call_ringing)
        CallPhase.RINGING_HERE -> stringResource(if (call.video) R.string.incoming_video_call else R.string.incoming_call)
        CallPhase.ACTIVE -> DateUtils.formatElapsedTime(((now - (call.answeredAt ?: now)) / 1000).coerceAtLeast(0))
        CallPhase.ENDED -> stringResource(endedText(call.ended))
    }
    if (video && unlocked && call.phase != CallPhase.RINGING_HERE && call.phase != CallPhase.ENDED) {
        return VideoCall(
            call, name, status, remoteFormat, onHangUp, onMute, onSpeaker, onCamera, onSwitchCamera,
            onLocalPreview, onRemoteView,
        )
    }
    val groupVideo = !oneToOne && (call.camera || call.memberCameras.values.any { it != VideoState.OFF })
    if (groupVideo && unlocked && call.phase == CallPhase.ACTIVE) {
        return GroupVideoCall(
            call, name, status, memberFormats, memberNames, onHangUp, onMute, onSpeaker, onCamera,
            onSwitchCamera, onLocalPreview, onMemberView, onAddPeople,
        )
    }

    CompositionLocalProvider(LocalContentColor provides Color.White) {
        Column(
            Modifier
                .fillMaxSize()
                .background(Brush.verticalGradient(listOf(CallTop, CallBottom)))
                .statusBarsPadding()
                .navigationBarsPadding()
                .padding(24.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            Spacer(Modifier.height(48.dp))
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                Icon(painterResource(R.drawable.ic_lock), contentDescription = null, modifier = Modifier.size(14.dp), tint = Muted)
                Text(stringResource(R.string.call_encrypted), style = MaterialTheme.typography.labelMedium, color = Muted)
            }
            Spacer(Modifier.height(32.dp))
            if (name != null) {
                Avatar(name, size = 128.dp, group = !oneToOne)
            } else {
                Box(
                    Modifier.size(128.dp).clip(CircleShape).background(Color.White.copy(alpha = 0.12f)),
                    contentAlignment = Alignment.Center,
                ) {
                    Icon(painterResource(R.drawable.ic_call), contentDescription = null, modifier = Modifier.size(56.dp))
                }
            }
            Spacer(Modifier.height(24.dp))
            Text(
                name ?: stringResource(R.string.call_incoming),
                style = MaterialTheme.typography.headlineMedium,
                textAlign = TextAlign.Center,
            )
            if (name == null) {
                Text(
                    stringResource(R.string.call_locked_caller),
                    style = MaterialTheme.typography.bodyMedium,
                    color = Muted,
                    textAlign = TextAlign.Center,
                )
            }
            if (detail != null) {
                Text(detail, style = MaterialTheme.typography.bodyLarge, color = Muted, textAlign = TextAlign.Center)
            }
            Spacer(Modifier.height(12.dp))
            Text(status, style = MaterialTheme.typography.titleMedium, color = CallAccent)
            if (video && !unlocked) {
                Text(
                    stringResource(R.string.video_locked),
                    style = MaterialTheme.typography.bodyMedium,
                    color = Muted,
                    textAlign = TextAlign.Center,
                    modifier = Modifier.padding(top = 8.dp),
                )
            }
            Spacer(Modifier.weight(1f))
            when (call.phase) {
                CallPhase.RINGING_HERE -> Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceEvenly) {
                    RoundButton(R.drawable.ic_call_end, R.string.call_decline, HangUp, onHangUp)
                    RoundButton(R.drawable.ic_call, R.string.call_answer, Answer, onAnswer)
                }
                CallPhase.ENDED -> Unit
                else -> Column(horizontalAlignment = Alignment.CenterHorizontally, verticalArrangement = Arrangement.spacedBy(28.dp)) {
                    Row(
                        Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceEvenly,
                        verticalAlignment = Alignment.Top,
                    ) {
                        Toggle(R.drawable.ic_mic, if (call.muted) R.string.call_unmute else R.string.call_mute, call.muted) {
                            onMute(it)
                        }
                        // A voice call becomes a video call when the camera goes on.
                        if (unlocked && (oneToOne || call.groupCameraRoom)) {
                            Toggle(R.drawable.ic_videocam, R.string.call_camera, false) { onCamera(true) }
                        }
                        onAddPeople?.let { add -> Toggle(R.drawable.ic_person_add, R.string.call_add_people, false) { add() } }
                        Toggle(R.drawable.ic_volume, if (call.speaker) R.string.call_earpiece else R.string.call_speaker, call.speaker) {
                            onSpeaker(it)
                        }
                    }
                    RoundButton(R.drawable.ic_call_end, R.string.call_hang_up, HangUp, onHangUp)
                }
            }
            Spacer(Modifier.height(32.dp))
        }
    }
}

private val Muted = Color.White.copy(alpha = 0.7f)

/** A 1:1 call with video: the contact full screen, this device's camera in a corner. Portrait only. */
@Composable
private fun VideoCall(
    call: CallUi,
    name: String?,
    status: String,
    remoteFormat: VideoFormat?,
    onHangUp: () -> Unit,
    onMute: (Boolean) -> Unit,
    onSpeaker: (Boolean) -> Unit,
    onCamera: (Boolean) -> Unit,
    onSwitchCamera: () -> Unit,
    onLocalPreview: (SurfaceTexture?) -> Unit,
    onRemoteView: (SurfaceTexture?) -> Unit,
) {
    val activity = LocalActivity.current
    DisposableEffect(activity) {
        val before = activity?.requestedOrientation
        activity?.requestedOrientation = ActivityInfo.SCREEN_ORIENTATION_PORTRAIT
        onDispose { if (before != null) activity.requestedOrientation = before }
    }
    Surface(Modifier.fillMaxSize(), color = Color.Black, contentColor = Color.White) {
        Box(Modifier.fillMaxSize()) {
            val remoteShown = call.phase == CallPhase.ACTIVE && call.remoteVideo == VideoState.ON
            if (call.phase == CallPhase.ACTIVE) {
                VideoView(
                    content = remoteFormat?.let {
                        val upright = if (it.rotation % 2 == 1) it.width <= it.height else it.height <= it.width
                        // A picture held upright fills the screen; one held sideways fits in it.
                        VideoTextureView.Content(it.width, it.height, it.rotation, fill = !upright)
                    },
                    onTexture = onRemoteView,
                    modifier = Modifier.fillMaxSize(),
                )
            }
            if (!remoteShown) {
                Column(Modifier.align(Alignment.Center), horizontalAlignment = Alignment.CenterHorizontally) {
                    Surface(shape = CircleShape, color = MaterialTheme.colorScheme.primaryContainer, modifier = Modifier.size(112.dp)) {
                        Box(contentAlignment = Alignment.Center) {
                            Text((name ?: "?").take(1).uppercase(), style = MaterialTheme.typography.displayMedium)
                        }
                    }
                    if (call.phase == CallPhase.ACTIVE) {
                        Text(
                            stringResource(
                                if (call.remoteVideo == VideoState.PAUSED) R.string.video_remote_paused else R.string.video_remote_off,
                            ),
                            style = MaterialTheme.typography.bodyLarge,
                            modifier = Modifier.padding(top = 16.dp),
                        )
                    }
                }
            }
            Column(
                Modifier
                    .align(Alignment.TopStart)
                    .statusBarsPadding()
                    .padding(start = 16.dp, top = 16.dp, end = 140.dp)
                    .background(Color.Black.copy(alpha = 0.35f), RoundedCornerShape(12.dp))
                    .padding(horizontal = 12.dp, vertical = 8.dp),
            ) {
                Text(name ?: "", style = MaterialTheme.typography.titleLarge)
                Text(status, style = MaterialTheme.typography.bodyMedium)
                Text(stringResource(R.string.call_encrypted), style = MaterialTheme.typography.labelSmall)
                if (call.videoWaits) {
                    Text(
                        stringResource(R.string.video_waits_wifi),
                        style = MaterialTheme.typography.bodySmall,
                        modifier = Modifier.padding(top = 4.dp),
                    )
                }
            }
            if (call.camera) {
                VideoView(
                    // The camera draws its preview upright and mirrored for the front camera; a phone
                    // held upright captures 16:9 sideways.
                    content = VideoTextureView.Content(9, 16),
                    onTexture = onLocalPreview,
                    modifier = Modifier
                        .align(Alignment.TopEnd)
                        .statusBarsPadding()
                        .padding(16.dp)
                        .width(108.dp)
                        .height(192.dp)
                        .clip(RoundedCornerShape(12.dp)),
                )
            }
            // Controls stay readable over any picture.
            Box(
                Modifier
                    .align(Alignment.BottomCenter)
                    .fillMaxWidth()
                    .height(240.dp)
                    .background(Brush.verticalGradient(listOf(Color.Transparent, Color.Black.copy(alpha = 0.6f)))),
            )
            Row(
                Modifier
                    .align(Alignment.BottomCenter)
                    .fillMaxWidth()
                    .navigationBarsPadding()
                    .padding(bottom = 24.dp),
                horizontalArrangement = Arrangement.SpaceEvenly,
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Toggle(R.drawable.ic_mic, if (call.muted) R.string.call_unmute else R.string.call_mute, call.muted) { onMute(it) }
                Toggle(if (call.camera) R.drawable.ic_videocam else R.drawable.ic_videocam_off, R.string.call_camera, call.camera) {
                    onCamera(it)
                }
                if (call.camera) {
                    Toggle(R.drawable.ic_switch_camera, R.string.call_switch_camera, false) { onSwitchCamera() }
                }
                Toggle(R.drawable.ic_volume, R.string.call_speaker, call.speaker) { onSpeaker(it) }
                RoundButton(R.drawable.ic_call_end, R.string.call_hang_up, HangUp, onHangUp)
            }
        }
    }
}

/**
 * A group call with cameras on: the pictures of the participants whose cameras are on (four at
 * most), this device's in a corner. Portrait only.
 */
@Composable
private fun GroupVideoCall(
    call: CallUi,
    name: String?,
    status: String,
    memberFormats: Map<Long, VideoFormat>,
    memberNames: Map<Long, String>,
    onHangUp: () -> Unit,
    onMute: (Boolean) -> Unit,
    onSpeaker: (Boolean) -> Unit,
    onCamera: (Boolean) -> Unit,
    onSwitchCamera: () -> Unit,
    onLocalPreview: (SurfaceTexture?) -> Unit,
    onMemberView: (Long, SurfaceTexture?) -> Unit,
    onAddPeople: (() -> Unit)?,
) {
    val activity = LocalActivity.current
    DisposableEffect(activity) {
        val before = activity?.requestedOrientation
        activity?.requestedOrientation = ActivityInfo.SCREEN_ORIENTATION_PORTRAIT
        onDispose { if (before != null) activity.requestedOrientation = before }
    }
    val shown = call.participants
        .filter { (call.memberCameras[it] ?: VideoState.OFF) != VideoState.OFF }
        .take(CallUi.MAX_GROUP_CAMERAS)
    Surface(Modifier.fillMaxSize(), color = Color.Black, contentColor = Color.White) {
        Box(Modifier.fillMaxSize()) {
            Column(Modifier.fillMaxSize().statusBarsPadding().navigationBarsPadding()) {
                Column(Modifier.padding(start = 16.dp, top = 16.dp, end = 140.dp, bottom = 8.dp)) {
                    Text(name ?: "", style = MaterialTheme.typography.titleLarge)
                    Text(status, style = MaterialTheme.typography.bodyMedium)
                    Text(stringResource(R.string.call_encrypted), style = MaterialTheme.typography.labelSmall)
                }
                Column(
                    Modifier.weight(1f).fillMaxWidth().padding(8.dp),
                    verticalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    if (shown.isEmpty()) {
                        Box(Modifier.weight(1f).fillMaxWidth(), contentAlignment = Alignment.Center) {
                            Text(stringResource(R.string.video_group_others_off), style = MaterialTheme.typography.bodyLarge)
                        }
                    }
                    // One or two pictures one above the other, three or four two by two.
                    for (row in shown.chunked(if (shown.size <= 2) 1 else 2)) {
                        Row(Modifier.weight(1f).fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                            for (member in row) {
                                key(member) {
                                    MemberTile(
                                        state = call.memberCameras[member] ?: VideoState.OFF,
                                        format = memberFormats[member],
                                        name = memberNames[member].orEmpty(),
                                        onTexture = { onMemberView(member, it) },
                                        modifier = Modifier.weight(1f).fillMaxHeight(),
                                    )
                                }
                            }
                        }
                    }
                }
                Row(
                    Modifier.fillMaxWidth().padding(vertical = 16.dp),
                    horizontalArrangement = Arrangement.SpaceEvenly,
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Toggle(R.drawable.ic_mic, if (call.muted) R.string.call_unmute else R.string.call_mute, call.muted) { onMute(it) }
                    if (call.camera || call.groupCameraRoom) {
                        Toggle(if (call.camera) R.drawable.ic_videocam else R.drawable.ic_videocam_off, R.string.call_camera, call.camera) {
                            onCamera(it)
                        }
                    }
                    if (call.camera) {
                        Toggle(R.drawable.ic_switch_camera, R.string.call_switch_camera, false) { onSwitchCamera() }
                    }
                    onAddPeople?.let { add -> Toggle(R.drawable.ic_person_add, R.string.call_add_people, false) { add() } }
                    Toggle(R.drawable.ic_volume, R.string.call_speaker, call.speaker) { onSpeaker(it) }
                    RoundButton(R.drawable.ic_call_end, R.string.call_hang_up, HangUp, onHangUp)
                }
            }
            if (call.camera) {
                VideoView(
                    content = VideoTextureView.Content(9, 16),
                    onTexture = onLocalPreview,
                    modifier = Modifier
                        .align(Alignment.TopEnd)
                        .statusBarsPadding()
                        .padding(16.dp)
                        .width(81.dp)
                        .height(144.dp)
                        .clip(RoundedCornerShape(12.dp)),
                )
            }
        }
    }
}

/** A group call participant's picture with its name; paused, only the name. */
@Composable
private fun MemberTile(
    state: VideoState,
    format: VideoFormat?,
    name: String,
    onTexture: (SurfaceTexture?) -> Unit,
    modifier: Modifier,
) {
    Box(modifier.clip(RoundedCornerShape(12.dp)).background(Color.DarkGray)) {
        if (state == VideoState.ON) {
            VideoView(
                content = format?.let { VideoTextureView.Content(it.width, it.height, it.rotation, fill = true) },
                onTexture = onTexture,
                modifier = Modifier.fillMaxSize(),
            )
        } else {
            Text(
                stringResource(R.string.video_remote_paused),
                style = MaterialTheme.typography.bodyMedium,
                modifier = Modifier.align(Alignment.Center),
            )
        }
        Text(
            name,
            style = MaterialTheme.typography.labelLarge,
            modifier = Modifier
                .align(Alignment.BottomStart)
                .padding(8.dp)
                .background(Color.Black.copy(alpha = 0.4f), RoundedCornerShape(6.dp))
                .padding(horizontal = 6.dp, vertical = 2.dp),
        )
    }
}

/** A [VideoTextureView] in Compose; [onTexture] hears of its texture, and of its end (null). */
@Composable
private fun VideoView(content: VideoTextureView.Content?, onTexture: (SurfaceTexture?) -> Unit, modifier: Modifier) {
    val callback by rememberUpdatedState(onTexture)
    AndroidView(
        factory = { context ->
            VideoTextureView(context).apply {
                surfaceTextureListener = object : TextureView.SurfaceTextureListener {
                    override fun onSurfaceTextureAvailable(texture: SurfaceTexture, width: Int, height: Int) = callback(texture)

                    override fun onSurfaceTextureSizeChanged(texture: SurfaceTexture, width: Int, height: Int) = Unit

                    // Kept: whoever draws into it releases it once it stopped.
                    override fun onSurfaceTextureDestroyed(texture: SurfaceTexture): Boolean {
                        callback(null)
                        return false
                    }

                    override fun onSurfaceTextureUpdated(texture: SurfaceTexture) = Unit
                }
            }
        },
        update = { it.content = content },
        modifier = modifier,
    )
}

@Composable
private fun RoundButton(@DrawableRes icon: Int, label: Int, color: Color, onClick: () -> Unit) {
    Column(horizontalAlignment = Alignment.CenterHorizontally, verticalArrangement = Arrangement.spacedBy(8.dp)) {
        FilledIconButton(
            onClick = onClick,
            modifier = Modifier.size(72.dp),
            colors = IconButtonDefaults.filledIconButtonColors(containerColor = color, contentColor = Color.White),
        ) {
            Icon(painterResource(icon), contentDescription = stringResource(label), modifier = Modifier.size(32.dp))
        }
        Text(stringResource(label), style = MaterialTheme.typography.labelLarge, color = Color.White)
    }
}

@Composable
private fun Toggle(@DrawableRes icon: Int, label: Int, checked: Boolean, onChange: (Boolean) -> Unit) {
    Column(horizontalAlignment = Alignment.CenterHorizontally, verticalArrangement = Arrangement.spacedBy(8.dp)) {
        FilledTonalIconToggleButton(
            checked = checked,
            onCheckedChange = onChange,
            modifier = Modifier.size(56.dp),
            colors = IconButtonDefaults.filledTonalIconToggleButtonColors(
                containerColor = Color.White.copy(alpha = 0.16f),
                contentColor = Color.White,
                checkedContainerColor = Color.White,
                checkedContentColor = CallBottom,
            ),
        ) {
            Icon(painterResource(icon), contentDescription = stringResource(label))
        }
        Text(stringResource(label), style = MaterialTheme.typography.labelMedium, color = Color.White)
    }
}

private fun endedText(reason: EndReason?): Int = when (reason) {
    EndReason.DECLINED -> R.string.call_declined
    EndReason.BUSY -> R.string.call_busy
    EndReason.NOT_ALLOWED -> R.string.call_not_allowed
    EndReason.NO_ANSWER -> R.string.call_no_answer
    EndReason.LOST -> R.string.call_lost
    else -> R.string.call_ended
}
