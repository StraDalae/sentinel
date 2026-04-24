package com.sentinel.app

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.provider.Settings
import android.view.View
import android.widget.Button
import android.widget.LinearLayout
import android.widget.TextView
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import androidx.core.view.WindowCompat

class OnboardingActivity : AppCompatActivity() {

    private var currentPage = 0
    private val totalPages = 3

    // Views
    private lateinit var pageContainer: LinearLayout
    private lateinit var nextBtn: Button
    private lateinit var indicator1: View
    private lateinit var indicator2: View
    private lateinit var indicator3: View

    // Permission launchers — fine location first, then background separately
    private val basePermissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestMultiplePermissions()
    ) { results ->
        val allGranted = results.values.all { it }
        if (allGranted) {
            // Fine location granted — now request background location separately
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                backgroundLocationLauncher.launch(Manifest.permission.ACCESS_BACKGROUND_LOCATION)
            } else {
                completeOnboarding()
            }
        } else {
            // Show a nudge — don't block them, but let them know
            nextBtn.text = "Continue Anyway"
            nextBtn.setOnClickListener { completeOnboarding() }
            showPermissionDeniedNote()
        }
    }

    private val backgroundLocationLauncher = registerForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) {
        // Whether granted or not, proceed — background location improves detection
        // but the app can still function without it
        completeOnboarding()
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        WindowCompat.setDecorFitsSystemWindows(window, false)

        setContentView(buildLayout())
        showPage(0)
    }

    private fun showPage(page: Int) {
        currentPage = page
        pageContainer.removeAllViews()

        when (page) {
            0 -> buildPage1()
            1 -> buildPage2()
            2 -> buildPage3()
        }

        // Update dot indicators
        val indicators = listOf(indicator1, indicator2, indicator3)
        indicators.forEachIndexed { index, view ->
            view.alpha = if (index == page) 1.0f else 0.3f
        }

        // Update button
        nextBtn.text = if (page < totalPages - 1) "Continue" else "Grant Permissions & Start"
        nextBtn.setOnClickListener {
            if (currentPage < totalPages - 1) {
                showPage(currentPage + 1)
            } else {
                requestAllPermissions()
            }
        }
    }

    // ── Page 1: What is Sentinel ──────────────────────────────────────────────

    private fun buildPage1() {
        val icon = TextView(this).apply {
            text = "⬡"
            textSize = 64f
            setTextColor(0xFF6366F1.toInt())
            gravity = android.view.Gravity.CENTER
        }

        val title = TextView(this).apply {
            text = "Stay aware.\nStay safe."
            textSize = 28f
            setTextColor(0xFFF1F5F9.toInt())
            gravity = android.view.Gravity.CENTER
            typeface = android.graphics.Typeface.DEFAULT_BOLD
            setPadding(0, 32, 0, 0)
        }

        val body = TextView(this).apply {
            text = "Bluetooth trackers are small, cheap, and increasingly used to follow people without their knowledge — in bags, under cars, or slipped into belongings.\n\nSentinel watches for devices that move with you across multiple locations and alerts you when something doesn't add up."
            textSize = 15f
            setTextColor(0xFF94A3B8.toInt())
            gravity = android.view.Gravity.CENTER
            setLineSpacing(0f, 1.5f)
            setPadding(0, 28, 0, 0)
        }

        pageContainer.addView(icon)
        pageContainer.addView(title)
        pageContainer.addView(body)
    }

    // ── Page 2: How it works ──────────────────────────────────────────────────

    private fun buildPage2() {
        val title = TextView(this).apply {
            text = "How Sentinel works"
            textSize = 26f
            setTextColor(0xFFF1F5F9.toInt())
            gravity = android.view.Gravity.CENTER
            typeface = android.graphics.Typeface.DEFAULT_BOLD
        }

        val bullets = listOf(
            "📡" to "Scans nearby Bluetooth devices in the background",
            "📍" to "Tracks which devices appear across multiple locations",
            "🔄" to "Analyzes signal strength, timing, and route patterns",
            "⚠️" to "Alerts you only when multiple suspicious signals align",
            "🔒" to "Everything stays on your device — nothing is ever uploaded"
        )

        val body = TextView(this).apply {
            text = bullets.joinToString("\n\n") { (icon, text) -> "$icon  $text" }
            textSize = 15f
            setTextColor(0xFF94A3B8.toInt())
            setLineSpacing(0f, 1.4f)
            setPadding(0, 32, 0, 0)
        }

        val note = TextView(this).apply {
            text = "Sentinel is designed to minimize false positives. A single device following you for one mile won't trigger an alert — it looks for persistent, multi-location patterns."
            textSize = 13f
            setTextColor(0xFF64748B.toInt())
            gravity = android.view.Gravity.CENTER
            setLineSpacing(0f, 1.4f)
            setPadding(0, 28, 0, 0)
        }

        pageContainer.addView(title)
        pageContainer.addView(body)
        pageContainer.addView(note)
    }

    // ── Page 3: Permissions ───────────────────────────────────────────────────

    private fun buildPage3() {
        val title = TextView(this).apply {
            text = "Before we start"
            textSize = 26f
            setTextColor(0xFFF1F5F9.toInt())
            gravity = android.view.Gravity.CENTER
            typeface = android.graphics.Typeface.DEFAULT_BOLD
        }

        val subtitle = TextView(this).apply {
            text = "Sentinel needs a few permissions to do its job. Here's exactly what each one is for:"
            textSize = 14f
            setTextColor(0xFF94A3B8.toInt())
            gravity = android.view.Gravity.CENTER
            setLineSpacing(0f, 1.4f)
            setPadding(0, 16, 0, 28)
        }

        val permissions = listOf(
            Triple("📍", "Precise Location", "Required to detect when you move between locations and associate nearby devices with where you were."),
            Triple("📡", "Bluetooth Scanning", "Required to detect nearby Bluetooth devices. Sentinel uses this to build device fingerprints — it never pairs with or connects to any device."),
            Triple("🗺️", "Background Location", "Allows Sentinel to keep watching while your screen is off. Without this, detection stops the moment you lock your phone."),
            Triple("🔔", "Notifications", "Required to alert you when a suspicious device is detected, even when the app isn't on screen.")
        )

        permissions.forEach { (icon, name, reason) ->
            val row = LinearLayout(this).apply {
                orientation = LinearLayout.HORIZONTAL
                setPadding(0, 0, 0, 20)
            }
            val iconView = TextView(this).apply {
                text = icon
                textSize = 20f
                setPadding(0, 2, 20, 0)
            }
            val textBlock = LinearLayout(this).apply {
                orientation = LinearLayout.VERTICAL
            }
            val nameView = TextView(this).apply {
                text = name
                textSize = 14f
                setTextColor(0xFFE2E8F0.toInt())
                typeface = android.graphics.Typeface.DEFAULT_BOLD
            }
            val reasonView = TextView(this).apply {
                text = reason
                textSize = 13f
                setTextColor(0xFF64748B.toInt())
                setLineSpacing(0f, 1.4f)
            }
            textBlock.addView(nameView)
            textBlock.addView(reasonView)
            row.addView(iconView)
            row.addView(textBlock)
            pageContainer.addView(row)
        }

        pageContainer.addView(title, 0)
        pageContainer.addView(subtitle, 1)
    }

    // ── Permission flow ───────────────────────────────────────────────────────

    private fun requestAllPermissions() {
        val base = mutableListOf(
            Manifest.permission.ACCESS_FINE_LOCATION,
            Manifest.permission.ACCESS_COARSE_LOCATION,
            Manifest.permission.BLUETOOTH_SCAN,
            Manifest.permission.BLUETOOTH_CONNECT,
        )
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU)
            base.add(Manifest.permission.POST_NOTIFICATIONS)

        val missing = base.filter {
            ContextCompat.checkSelfPermission(this, it) != PackageManager.PERMISSION_GRANTED
        }

        if (missing.isEmpty()) {
            // Base permissions already granted — go straight to background location
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q &&
                ContextCompat.checkSelfPermission(this, Manifest.permission.ACCESS_BACKGROUND_LOCATION)
                != PackageManager.PERMISSION_GRANTED) {
                backgroundLocationLauncher.launch(Manifest.permission.ACCESS_BACKGROUND_LOCATION)
            } else {
                completeOnboarding()
            }
        } else {
            basePermissionLauncher.launch(missing.toTypedArray())
        }
    }

    private fun showPermissionDeniedNote() {
        val note = TextView(this).apply {
            text = "Some permissions were denied. Sentinel may not work correctly. You can grant them later in Settings."
            textSize = 13f
            setTextColor(0xFFFBBF24.toInt())
            gravity = android.view.Gravity.CENTER
            setLineSpacing(0f, 1.4f)
            setPadding(0, 16, 0, 0)
        }
        pageContainer.addView(note)
    }

    private fun completeOnboarding() {
        getSharedPreferences("sentinel_prefs", MODE_PRIVATE)
            .edit()
            .putBoolean("onboarding_complete", true)
            .apply()
        startActivity(Intent(this, MainActivity::class.java))
        finish()
    }

    // ── Layout builder ────────────────────────────────────────────────────────

    private fun buildLayout(): View {
        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setBackgroundColor(0xFF0F1117.toInt())
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.MATCH_PARENT
            )
        }

        // Page content area
        pageContainer = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            gravity = android.view.Gravity.CENTER
            setPadding(64, 80, 64, 40)
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                0,
                1f
            )
        }

        // Dot indicators
        val indicatorRow = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = android.view.Gravity.CENTER
            setPadding(0, 0, 0, 24)
        }
        fun makeDot() = View(this).apply {
            layoutParams = LinearLayout.LayoutParams(20, 20).apply { setMargins(8, 0, 8, 0) }
            background = android.graphics.drawable.GradientDrawable().apply {
                shape = android.graphics.drawable.GradientDrawable.OVAL
                setColor(0xFF6366F1.toInt())
            }
        }
        indicator1 = makeDot()
        indicator2 = makeDot()
        indicator3 = makeDot()
        indicatorRow.addView(indicator1)
        indicatorRow.addView(indicator2)
        indicatorRow.addView(indicator3)

        // Next button
        nextBtn = Button(this).apply {
            textSize = 15f
            setTextColor(0xFFFFFFFF.toInt())
            background = android.graphics.drawable.GradientDrawable().apply {
                setColor(0xFF6366F1.toInt())
                cornerRadius = 16f
            }
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
            ).apply { setMargins(64, 0, 64, 48) }
            setPadding(0, 32, 0, 32)
        }

        root.addView(pageContainer)
        root.addView(indicatorRow)
        root.addView(nextBtn)
        return root
    }
}
