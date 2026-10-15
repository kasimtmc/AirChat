package com.plyg.airchat.ui.screens

import android.app.Activity
import android.content.Context
import android.content.Intent
import android.graphics.SurfaceTexture
import android.media.MediaDataSource
import android.media.MediaPlayer
import android.net.Uri
import android.text.format.DateUtils
import android.text.format.Formatter
import android.view.Surface
import android.view.TextureView
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContract
import androidx.annotation.StringRes
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.gestures.rememberTransformableState
import androidx.compose.foundation.gestures.transformable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.aspectRatio
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilledIconButton
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Slider
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableFloatStateOf
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.produceState
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.viewinterop.AndroidView
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import androidx.compose.ui.window.SecureFlagPolicy
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import androidx.lifecycle.compose.LocalLifecycleOwner
import androidx.compose.material3.IconButton
import com.plyg.airchat.R
import com.plyg.airchat.ui.Files
import com.plyg.airchat.ui.Viewer
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext

/**
 * A stored file in an in-app viewer (requirement S-10), full screen and, like every AirChat window,
 * hidden from screenshots. Saving it outside AirChat takes an explicit warning first.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun FileViewer(
    viewer: Viewer,
    @StringRes notice: Int?,
    @StringRes error: Int?,
    onClose: () -> Unit,
    /** The user confirmed the warning; [onExportTo] follows with where they chose, or null. */
    onExport: () -> Unit,
    onExportTo: (Uri?) -> Unit,
) {
    val attachment = viewer.file.attachment
    var warn by remember { mutableStateOf(false) }
    val createDocument = rememberLauncherForActivityResult(CreateDocument(), onExportTo)

    Dialog(
        onDismissRequest = onClose,
        properties = DialogProperties(usePlatformDefaultWidth = false, securePolicy = SecureFlagPolicy.SecureOn),
    ) {
        Scaffold(
            topBar = {
                TopAppBar(
                    navigationIcon = {
                        IconButton(onClick = onClose) {
                            Icon(painterResource(R.drawable.ic_close), contentDescription = stringResource(R.string.close))
                        }
                    },
                    title = { Text(attachment.name, maxLines = 1, overflow = TextOverflow.Ellipsis) },
                    actions = {
                        IconButton(onClick = { warn = true }) {
                            Icon(painterResource(R.drawable.ic_download), contentDescription = stringResource(R.string.file_save))
                        }
                    },
                )
            },
            bottomBar = {
                Box(Modifier.fillMaxWidth().padding(16.dp)) {
                    ErrorText(error)
                    if (error == null && notice != null) {
                        Text(stringResource(notice), color = MaterialTheme.colorScheme.primary, style = MaterialTheme.typography.bodyMedium)
                    }
                }
            },
        ) { padding ->
            Box(Modifier.fillMaxSize().padding(padding), contentAlignment = Alignment.Center) {
                when (viewer) {
                    is Viewer.Image -> ZoomableImage(viewer)
                    is Viewer.Text -> SelectionContainer(Modifier.fillMaxSize()) {
                        Text(
                            viewer.text,
                            fontFamily = FontFamily.Monospace,
                            style = MaterialTheme.typography.bodySmall,
                            modifier = Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp),
                        )
                    }
                    is Viewer.Media -> MediaPlayerView(viewer.source, viewer.video)
                    is Viewer.Pdf -> PdfPages(viewer.document)
                    is Viewer.Other -> Column(
                        Modifier.padding(32.dp),
                        horizontalAlignment = Alignment.CenterHorizontally,
                        verticalArrangement = Arrangement.spacedBy(12.dp),
                    ) {
                        Icon(painterResource(R.drawable.ic_file), contentDescription = null, modifier = Modifier.size(64.dp))
                        Text(attachment.name, style = MaterialTheme.typography.titleMedium)
                        Text(Formatter.formatShortFileSize(LocalContext.current, attachment.size.toLong()))
                        Text(stringResource(R.string.file_no_viewer), style = MaterialTheme.typography.bodyMedium)
                    }
                }
            }
        }

        if (warn) {
            AlertDialog(
                onDismissRequest = { warn = false },
                title = { Text(stringResource(R.string.export_warning_title)) },
                text = { Text(stringResource(R.string.export_warning_body)) },
                confirmButton = {
                    TextButton(onClick = {
                        warn = false
                        onExport()
                        createDocument.launch(attachment.name to attachment.mime)
                    }) { Text(stringResource(R.string.export_confirm)) }
                },
                dismissButton = { TextButton(onClick = { warn = false }) { Text(stringResource(R.string.cancel)) } },
            )
        }
    }
}

@Composable
private fun ZoomableImage(viewer: Viewer.Image) {
    var scale by remember { mutableFloatStateOf(1f) }
    var offsetX by remember { mutableFloatStateOf(0f) }
    var offsetY by remember { mutableFloatStateOf(0f) }
    val transform = rememberTransformableState { zoom, pan, _ ->
        scale = (scale * zoom).coerceIn(1f, 8f)
        if (scale == 1f) {
            offsetX = 0f
            offsetY = 0f
        } else {
            offsetX += pan.x
            offsetY += pan.y
        }
    }
    Image(
        viewer.bitmap,
        contentDescription = viewer.file.attachment.name,
        contentScale = ContentScale.Fit,
        modifier = Modifier
            .fillMaxSize()
            .transformable(transform)
            .graphicsLayer(scaleX = scale, scaleY = scale, translationX = offsetX, translationY = offsetY),
    )
}

/** The pages of a PDF, each rendered in memory when it comes into view. */
@Composable
private fun PdfPages(document: Files.PdfDocument) {
    BoxWithConstraints(Modifier.fillMaxSize()) {
        val width = constraints.maxWidth
        LazyColumn(
            Modifier.fillMaxSize().background(MaterialTheme.colorScheme.surfaceVariant),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            items(document.pageCount) { index ->
                val page by produceState<ImageBitmap?>(null, document, index, width) {
                    value = withContext(Dispatchers.Default) { document.render(index, width)?.asImageBitmap() }
                }
                val bitmap = page
                if (bitmap != null) {
                    Image(
                        bitmap,
                        contentDescription = null,
                        contentScale = ContentScale.FillWidth,
                        modifier = Modifier.fillMaxWidth(),
                    )
                } else {
                    Box(Modifier.fillMaxWidth().aspectRatio(1f / 1.414f).background(Color.White))
                }
            }
        }
    }
}

/** Plays a video or audio file from a [MediaDataSource]; nothing is written anywhere. */
@Composable
private fun MediaPlayerView(source: MediaDataSource, video: Boolean) {
    var player by remember { mutableStateOf<MediaPlayer?>(null) }
    var surface by remember { mutableStateOf<Surface?>(null) }
    var playing by remember { mutableStateOf(false) }
    var duration by remember { mutableIntStateOf(0) }
    var position by remember { mutableIntStateOf(0) }
    var aspect by remember { mutableFloatStateOf(16f / 9f) }
    var failed by remember { mutableStateOf(false) }

    DisposableEffect(source) {
        val media = MediaPlayer()
        media.setOnPreparedListener {
            duration = it.duration
            it.start()
            playing = true
            player = it
        }
        media.setOnVideoSizeChangedListener { _, width, height ->
            if (width > 0 && height > 0) aspect = width.toFloat() / height
        }
        media.setOnCompletionListener { playing = false }
        media.setOnErrorListener { _, _, _ ->
            failed = true
            playing = false
            true
        }
        try {
            media.setDataSource(source)
            media.prepareAsync()
        } catch (_: Exception) {
            failed = true
        }
        onDispose {
            player = null
            media.release()
        }
    }
    LaunchedEffect(player, surface) { player?.setSurface(surface) }
    LaunchedEffect(player) {
        while (true) {
            player?.takeIf { playing }?.let { position = it.currentPosition }
            delay(250)
        }
    }
    // Stop when the app leaves the screen.
    val lifecycle = LocalLifecycleOwner.current.lifecycle
    DisposableEffect(lifecycle) {
        val observer = LifecycleEventObserver { _, event ->
            if (event == Lifecycle.Event.ON_STOP && playing) {
                player?.pause()
                playing = false
            }
        }
        lifecycle.addObserver(observer)
        onDispose { lifecycle.removeObserver(observer) }
    }

    if (failed) {
        Text(stringResource(R.string.media_failed), modifier = Modifier.padding(32.dp))
        return
    }
    Column(Modifier.fillMaxWidth(), horizontalAlignment = Alignment.CenterHorizontally) {
        if (video) {
            AndroidView(
                factory = { context -> videoView(context) { surface = it } },
                modifier = Modifier.fillMaxWidth().aspectRatio(aspect),
            )
        }
        Row(
            Modifier.fillMaxWidth().padding(16.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            FilledIconButton(
                onClick = {
                    val media = player ?: return@FilledIconButton
                    if (playing) media.pause() else media.start()
                    playing = !playing
                },
                enabled = player != null,
            ) {
                Icon(
                    painterResource(if (playing) R.drawable.ic_pause else R.drawable.ic_play),
                    contentDescription = stringResource(if (playing) R.string.pause else R.string.play),
                )
            }
            Slider(
                value = position.toFloat(),
                onValueChange = {
                    position = it.toInt()
                    player?.seekTo(position)
                },
                valueRange = 0f..duration.coerceAtLeast(1).toFloat(),
                enabled = player != null,
                modifier = Modifier.weight(1f),
            )
            Text(
                DateUtils.formatElapsedTime(position / 1000L) + " / " + DateUtils.formatElapsedTime(duration / 1000L),
                style = MaterialTheme.typography.labelSmall,
            )
        }
    }
}

/** A TextureView draws into the window's own surface, so the window's FLAG_SECURE covers it. */
private fun videoView(context: Context, onSurface: (Surface?) -> Unit) = TextureView(context).apply {
    surfaceTextureListener = object : TextureView.SurfaceTextureListener {
        private var surface: Surface? = null

        override fun onSurfaceTextureAvailable(texture: SurfaceTexture, width: Int, height: Int) {
            surface = Surface(texture).also(onSurface)
        }

        override fun onSurfaceTextureDestroyed(texture: SurfaceTexture): Boolean {
            onSurface(null)
            surface?.release()
            surface = null
            return true
        }

        override fun onSurfaceTextureSizeChanged(texture: SurfaceTexture, width: Int, height: Int) = Unit

        override fun onSurfaceTextureUpdated(texture: SurfaceTexture) = Unit
    }
}

/** "Save as" with the file's own name and type. */
private class CreateDocument : ActivityResultContract<Pair<String, String>, Uri?>() {
    override fun createIntent(context: Context, input: Pair<String, String>): Intent =
        Intent(Intent.ACTION_CREATE_DOCUMENT)
            .addCategory(Intent.CATEGORY_OPENABLE)
            .setType(input.second)
            .putExtra(Intent.EXTRA_TITLE, input.first)

    override fun parseResult(resultCode: Int, intent: Intent?): Uri? =
        intent?.data?.takeIf { resultCode == Activity.RESULT_OK }
}
