package com.plyg.airchat.ui

import android.content.ClipData
import android.content.ClipDescription
import android.content.ClipboardManager
import android.annotation.SuppressLint
import android.content.Context
import android.os.Handler
import android.os.Looper
import android.os.PersistableBundle
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.remember
import androidx.compose.ui.platform.AndroidClipboard
import androidx.compose.ui.platform.ClipEntry
import androidx.compose.ui.platform.LocalClipboard
import androidx.compose.ui.platform.nativeClipboardManager
import java.security.SecureRandom

/**
 * What is copied in AirChat (requirement S-9): marked sensitive, so the system's clipboard preview
 * and keyboards do not show it, and cleared after [CLEAR_AFTER_MS] unless something else was copied
 * meanwhile. Android lets only the app in front read the clipboard: if the time runs out in the
 * background, it is cleared when AirChat comes back to the front, and when it locks.
 */
class SensitiveClipboard(context: Context) {
    private val manager = context.getSystemService(ClipboardManager::class.java)

    /** Names this app's clips, so it never clears one copied elsewhere. */
    private val label = "AirChat " + ByteArray(8).also(SecureRandom()::nextBytes).joinToString("") { "%02x".format(it) }
    private val handler = Handler(Looper.getMainLooper())
    private var due = false
    private val expire = Runnable {
        due = true
        clearIfOurs()
    }

    /** `clip`, as this app copies it: sensitive, and named as its own. */
    fun mark(clip: ClipData): ClipData {
        val marked = ClipData(label, Array(clip.description.mimeTypeCount) { clip.description.getMimeType(it) }, clip.getItemAt(0))
        for (index in 1 until clip.itemCount) marked.addItem(clip.getItemAt(index))
        marked.description.extras = PersistableBundle().apply { putBoolean(EXTRA_IS_SENSITIVE, true) }
        return marked
    }

    /** Something was just copied: it goes after a while. */
    fun copied() {
        due = false
        handler.removeCallbacks(expire)
        handler.postDelayed(expire, CLEAR_AFTER_MS)
    }

    /** AirChat locked: what it copied goes now (or as soon as it can tell it is still there). */
    fun locked() {
        handler.removeCallbacks(expire)
        due = true
        clearIfOurs()
    }

    /** Clears a clip whose time is up, if it is this app's; in the background it stays due. */
    fun clearIfOurs() {
        if (!due) return
        val description = runCatching { manager?.primaryClipDescription }.getOrNull() ?: return
        due = false
        if (description.label == label) manager?.clearPrimaryClip()
    }

    private companion object {
        const val CLEAR_AFTER_MS = 60_000L

        /** [ClipDescription.EXTRA_IS_SENSITIVE], which needs API 33 as a constant. */
        const val EXTRA_IS_SENSITIVE = "android.content.extra.IS_SENSITIVE"
    }
}

/**
 * The clipboard copies inside [content] go through: those of text fields and selections too. It is
 * an [AndroidClipboard], as text fields ask the platform clipboard directly whether there is
 * something to paste (and fail on any other kind).
 */
// AndroidClipboard is public but marked for tests; text fields require it of LocalClipboard.
@SuppressLint("VisibleForTests")
@Composable
fun SensitiveCopies(clipboard: SensitiveClipboard, content: @Composable () -> Unit) {
    val platform = LocalClipboard.current
    val sensitive = remember(platform, clipboard) {
        object : AndroidClipboard {
            override val clipboardManager: ClipboardManager get() = platform.nativeClipboardManager

            override suspend fun getClipEntry(): ClipEntry? = platform.getClipEntry()

            override suspend fun setClipEntry(clipEntry: ClipEntry?) {
                if (clipEntry == null) return platform.setClipEntry(null)
                platform.setClipEntry(ClipEntry(clipboard.mark(clipEntry.clipData)))
                clipboard.copied()
            }
        }
    }
    CompositionLocalProvider(LocalClipboard provides sensitive, content = content)
}
