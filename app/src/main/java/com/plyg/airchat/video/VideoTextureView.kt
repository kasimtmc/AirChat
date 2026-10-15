package com.plyg.airchat.video

import android.content.Context
import android.graphics.Matrix
import android.view.TextureView
import kotlin.math.max
import kotlin.math.min

/**
 * A [TextureView] that shows a picture of [Content]'s size upright and undistorted: the texture is
 * stretched over the view, so the transform undoes that, turns the picture, then fits it in the view
 * or fills the view with it. Keeps the screen on while shown.
 */
class VideoTextureView(context: Context) : TextureView(context) {
    /** The picture as it arrives: its size, quarter turns clockwise to show it upright, and how. */
    data class Content(
        val width: Int,
        val height: Int,
        val rotation: Int = 0,
        /** Fill the view (cutting the edges off) rather than fit in it (leaving bars). */
        val fill: Boolean = true,
        /** Mirrored left to right, as people expect of themselves. */
        val mirror: Boolean = false,
    )

    var content: Content? = null
        set(value) {
            if (field == value) return
            field = value
            updateTransform()
        }

    init {
        keepScreenOn = true
    }

    override fun onSizeChanged(w: Int, h: Int, oldw: Int, oldh: Int) {
        super.onSizeChanged(w, h, oldw, oldh)
        updateTransform()
    }

    private fun updateTransform() {
        val content = content
        val (viewWidth, viewHeight) = width.toFloat() to height.toFloat()
        if (content == null || viewWidth <= 0f || viewHeight <= 0f || content.width <= 0 || content.height <= 0) {
            return setTransform(null)
        }
        val (cx, cy) = viewWidth / 2 to viewHeight / 2
        val turned = content.rotation % 2 == 1
        val (shownWidth, shownHeight) = if (turned) {
            content.height.toFloat() to content.width.toFloat()
        } else {
            content.width.toFloat() to content.height.toFloat()
        }
        val scale = if (content.fill) {
            max(viewWidth / shownWidth, viewHeight / shownHeight)
        } else {
            min(viewWidth / shownWidth, viewHeight / shownHeight)
        }
        val matrix = Matrix().apply {
            // From stretched over the view to the picture's own size, then turned, then scaled.
            setScale(content.width / viewWidth, content.height / viewHeight, cx, cy)
            postRotate(content.rotation * 90f, cx, cy)
            postScale(if (content.mirror) -scale else scale, scale, cx, cy)
        }
        setTransform(matrix)
    }
}
