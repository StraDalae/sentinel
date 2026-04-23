package com.sentinel.app

import android.Manifest
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.content.pm.PackageManager
import android.graphics.Color
import android.os.Build
import android.os.Bundle
import android.os.IBinder
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import androidx.core.view.GravityCompat
import androidx.drawerlayout.widget.DrawerLayout
import com.google.android.gms.maps.CameraUpdateFactory
import com.google.android.gms.maps.GoogleMap
import com.google.android.gms.maps.OnMapReadyCallback
import com.google.android.gms.maps.SupportMapFragment
import com.google.android.gms.maps.model.*
import com.sentinel.app.databinding.ActivityMainBinding
import com.sentinel.app.db.AppDatabase
import com.sentinel.app.model.DeviceSighting
import com.sentinel.app.service.ScannerService
import com.sentinel.app.threat.ThreatDetector
import kotlinx.coroutines.*

class MainActivity : AppCompatActivity(), OnMapReadyCallback {

    private lateinit var binding: ActivityMainBinding
    private var googleMap: GoogleMap? = null
    private var scannerService: ScannerService? = null
    private var isBound = false
    private val markers = mutableMapOf<String, Marker>()
    private val scope = CoroutineScope(Dispatchers.Main + SupervisorJob())

    private var mapReady = false
    private val pendingMarkers = mutableListOf<DeviceSighting>()
    private val threatPaths = mutableMapOf<String, Polyline>()

    private enum class AlertState { NONE, WARN, THREAT }
    private var currentAlertState = AlertState.NONE

    private val serviceConnection = object : ServiceConnection {
        override fun onServiceConnected(name: ComponentName?, binder: IBinder?) {
            val localBinder = binder as ScannerService.LocalBinder
            scannerService = localBinder.getService()
            isBound = true

            val scanning = scannerService?.isScanning ?: false
            binding.scanToggle.isChecked = scanning
            updateStatusText(scanning)

            val cached = scannerService?.recentSightings?.values ?: emptyList()
            binding.nearbyCountText.text = "${cached.size} nearby"
            cached.forEach { addOrUpdateMarker(it) }
            updateFlaggedCount()

            scannerService?.currentLocation?.let { loc ->
                googleMap?.animateCamera(
                    CameraUpdateFactory.newLatLngZoom(LatLng(loc.latitude, loc.longitude), 16f)
                )
            }

            observeService()
        }

        override fun onServiceDisconnected(name: ComponentName?) {
            scannerService = null
            isBound = false
        }
    }

    private val permissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestMultiplePermissions()
    ) { permissions ->
        if (permissions.values.all { it }) startScanning()
        else {
            Toast.makeText(this, "Permissions required for scanning", Toast.LENGTH_LONG).show()
            binding.scanToggle.isChecked = false
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)

        val mapFragment = supportFragmentManager
            .findFragmentById(R.id.map) as SupportMapFragment
        mapFragment.getMapAsync(this)

        binding.scanToggle.setOnCheckedChangeListener { _, isChecked ->
            if (isChecked) checkPermissionsAndStart() else stopScanning()
        }
        binding.clearBtn.setOnClickListener { clearMap() }

        binding.menuBtn.setOnClickListener {
            binding.drawerLayout.openDrawer(GravityCompat.START)
        }
        binding.menuItem1.setOnClickListener {
            binding.drawerLayout.closeDrawer(GravityCompat.START)
            Toast.makeText(this, "Device History — coming soon", Toast.LENGTH_SHORT).show()
        }
        binding.menuItem2.setOnClickListener {
            binding.drawerLayout.closeDrawer(GravityCompat.START)
            Toast.makeText(this, "Settings — coming soon", Toast.LENGTH_SHORT).show()
        }
        binding.menuItem3.setOnClickListener {
            binding.drawerLayout.closeDrawer(GravityCompat.START)
            Toast.makeText(this, "Export Report — coming soon", Toast.LENGTH_SHORT).show()
        }

        binding.drawerLayout.addDrawerListener(object : DrawerLayout.SimpleDrawerListener() {})
    }

    override fun onStart() {
        super.onStart()
        bindService(Intent(this, ScannerService::class.java), serviceConnection, 0)
    }

    override fun onStop() {
        super.onStop()
        if (isBound) {
            unbindService(serviceConnection)
            isBound = false
            scannerService = null
        }
    }

    override fun onBackPressed() {
        if (binding.drawerLayout.isDrawerOpen(GravityCompat.START)) {
            binding.drawerLayout.closeDrawer(GravityCompat.START)
        } else {
            super.onBackPressed()
        }
    }

    override fun onMapReady(map: GoogleMap) {
        googleMap = map
        mapReady = true
        map.uiSettings.isZoomControlsEnabled = true

        try {
            map.setMapStyle(MapStyleOptions.loadRawResourceStyle(this, R.raw.map_style_dark))
        } catch (e: Exception) {}

        if (ContextCompat.checkSelfPermission(this, Manifest.permission.ACCESS_FINE_LOCATION)
            == PackageManager.PERMISSION_GRANTED) {
            map.isMyLocationEnabled = true
        }

        map.setOnMarkerClickListener { marker ->
            val fingerprint = markers.entries.firstOrNull { it.value == marker }?.key
            if (fingerprint != null) {
                val sighting = scannerService?.recentSightings?.get(fingerprint)
                if (sighting != null &&
                    sighting.threatScore >= ThreatDetector.SCORE_ALERT_THRESHOLD) {
                    loadAndDrawThreatPath(fingerprint)
                }
            }
            false
        }

        pendingMarkers.forEach { addOrUpdateMarker(it) }
        pendingMarkers.clear()

        scannerService?.currentLocation?.let { loc ->
            map.moveCamera(CameraUpdateFactory.newLatLngZoom(LatLng(loc.latitude, loc.longitude), 16f))
        }
    }

    // ── Threat path ───────────────────────────────────────────────────────────

    private fun loadAndDrawThreatPath(fingerprint: String) {
        scope.launch {
            val db = AppDatabase.getInstance(this@MainActivity)
            val history = withContext(Dispatchers.IO) {
                db.sightingDao().getSightingsForDevice(
                    fingerprint = fingerprint,
                    since = System.currentTimeMillis() - ThreatDetector.HISTORY_WINDOW_MS
                )
            }
            if (history.size < 2) return@launch

            val points = history.sortedBy { it.timestamp }.map { LatLng(it.latitude, it.longitude) }

            threatPaths[fingerprint]?.remove()
            val polyline = googleMap?.addPolyline(
                PolylineOptions()
                    .addAll(points)
                    .color(Color.parseColor("#FFFF1744"))
                    .width(8f)
                    .geodesic(true)
                    .pattern(listOf(Dot(), Gap(12f)))
            )
            polyline?.let { threatPaths[fingerprint] = it }

            history.sortedBy { it.timestamp }.forEachIndexed { index, s ->
                googleMap?.addMarker(
                    MarkerOptions()
                        .position(LatLng(s.latitude, s.longitude))
                        .icon(BitmapDescriptorFactory.defaultMarker(
                            if (index == 0) BitmapDescriptorFactory.HUE_ORANGE
                            else BitmapDescriptorFactory.HUE_RED
                        ))
                        .title(if (index == 0) "First seen" else "Stop ${index + 1}")
                        .snippet("Signal: ${s.rssi} dBm")
                        .alpha(0.75f)
                )
            }

            val bounds = points.fold(LatLngBounds.builder()) { b, p -> b.include(p) }.build()
            googleMap?.animateCamera(CameraUpdateFactory.newLatLngBounds(bounds, 120))
        }
    }

    // ── Bottom bar glow ───────────────────────────────────────────────────────

    private fun updateBottomGlow(state: AlertState) {
        if (state == currentAlertState) return
        currentAlertState = state
        binding.bottomGlow.setBackgroundResource(when (state) {
            AlertState.THREAT -> R.drawable.glow_red
            AlertState.WARN   -> R.drawable.glow_yellow
            AlertState.NONE   -> R.drawable.glow_none
        })
    }

    // ── Scanning control ──────────────────────────────────────────────────────

    private fun checkPermissionsAndStart() {
        val needed = mutableListOf(
            Manifest.permission.ACCESS_FINE_LOCATION,
            Manifest.permission.ACCESS_COARSE_LOCATION,
            Manifest.permission.BLUETOOTH_SCAN,
            Manifest.permission.BLUETOOTH_CONNECT,
            Manifest.permission.FOREGROUND_SERVICE,
        )
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU)
            needed.add(Manifest.permission.POST_NOTIFICATIONS)
        val missing = needed.filter {
            ContextCompat.checkSelfPermission(this, it) != PackageManager.PERMISSION_GRANTED
        }
        if (missing.isEmpty()) startScanning()
        else permissionLauncher.launch(missing.toTypedArray())
    }

    private fun startScanning() {
        val intent = Intent(this, ScannerService::class.java)
        intent.action = ScannerService.ACTION_START
        ContextCompat.startForegroundService(this, intent)
        updateStatusText(true)
    }

    private fun stopScanning() {
        val intent = Intent(this, ScannerService::class.java)
        intent.action = ScannerService.ACTION_STOP
        startService(intent)
        updateStatusText(false)
        binding.nearbyCountText.text = "0 nearby"
        binding.deviceCountText.text = "0 flagged"
        googleMap?.clear()
        markers.clear()
        threatPaths.clear()
        updateBottomGlow(AlertState.NONE)
    }

    private fun updateStatusText(scanning: Boolean) {
        if (scanning) {
            binding.statusText.text = "● SCANNING"
            binding.statusText.setTextColor(getColor(R.color.threat_green))
        } else {
            binding.statusText.text = "○ INACTIVE"
            binding.statusText.setTextColor(getColor(R.color.text_muted))
        }
    }

    // ── Service observation ───────────────────────────────────────────────────

    private fun observeService() {
        scannerService?.onNearbyCountChanged = { count ->
            runOnUiThread { binding.nearbyCountText.text = "$count nearby" }
        }
        scannerService?.onNewSighting = { sighting ->
            runOnUiThread {
                addOrUpdateMarker(sighting)
                updateFlaggedCount()
            }
        }
    }

    // ── Map markers ───────────────────────────────────────────────────────────

    private fun addOrUpdateMarker(sighting: DeviceSighting) {
        if (!mapReady) {
            pendingMarkers.removeAll { it.deviceFingerprint == sighting.deviceFingerprint }
            pendingMarkers.add(sighting)
            return
        }

        val latLng = LatLng(sighting.latitude, sighting.longitude)
        val level = when {
            sighting.threatScore >= ThreatDetector.SCORE_ALERT_THRESHOLD -> ThreatLevel.HIGH
            sighting.threatScore >= ThreatDetector.SCORE_WARN_THRESHOLD  -> ThreatLevel.MEDIUM
            else -> ThreatLevel.SAFE
        }
        val title = when (level) {
            ThreatLevel.HIGH   -> "⚠ Threat · Score ${sighting.threatScore} — tap for path"
            ThreatLevel.MEDIUM -> "? Watching · Score ${sighting.threatScore}"
            ThreatLevel.SAFE   -> "● Nearby device"
        }
        val snippet = "RSSI ${sighting.rssi} dBm · ${sighting.deviceFingerprint.take(8)}..."

        val existing = markers[sighting.deviceFingerprint]
        if (existing != null) {
            existing.position = latLng
            existing.setIcon(markerIcon(level))
            existing.title = title
        } else {
            val marker = googleMap?.addMarker(
                MarkerOptions()
                    .position(latLng)
                    .title(title)
                    .snippet(snippet)
                    .icon(markerIcon(level))
                    .alpha(if (level == ThreatLevel.SAFE) 0.5f else 1.0f)
            )
            marker?.let { markers[sighting.deviceFingerprint] = it }
        }

        if (level == ThreatLevel.HIGH) {
            googleMap?.animateCamera(CameraUpdateFactory.newLatLngZoom(latLng, 16f))
        }
    }

    private enum class ThreatLevel { SAFE, MEDIUM, HIGH }

    private fun markerIcon(level: ThreatLevel) = when (level) {
        ThreatLevel.HIGH   -> BitmapDescriptorFactory.defaultMarker(BitmapDescriptorFactory.HUE_RED)
        ThreatLevel.MEDIUM -> BitmapDescriptorFactory.defaultMarker(BitmapDescriptorFactory.HUE_YELLOW)
        ThreatLevel.SAFE   -> BitmapDescriptorFactory.defaultMarker(BitmapDescriptorFactory.HUE_CYAN)
    }

    private fun updateFlaggedCount() {
        val threats  = markers.values.count { it.title?.startsWith("⚠") == true }
        val watching = markers.values.count { it.title?.startsWith("?") == true }
        binding.deviceCountText.text = "${threats + watching} flagged"
        updateBottomGlow(when {
            threats  > 0 -> AlertState.THREAT
            watching > 0 -> AlertState.WARN
            else         -> AlertState.NONE
        })
    }

    // ── Clear ─────────────────────────────────────────────────────────────────

    private fun clearMap() {
        // 1. Wipe the map visuals and local marker tracking
        googleMap?.clear()
        markers.clear()
        threatPaths.clear()
        pendingMarkers.clear()
        binding.nearbyCountText.text = "0 nearby"
        binding.deviceCountText.text = "0 flagged"
        updateBottomGlow(AlertState.NONE)

        // 2. Tell the service to forget every fingerprint it has seen.
        //    This makes all currently-nearby devices "new" again on the next
        //    scan result, so they immediately reappear on the map without
        //    needing to leave range and come back.
        scannerService?.clearSession()

        // 3. Wipe the persistent DB so historical threat scores reset too
        scope.launch(Dispatchers.IO) {
            AppDatabase.getInstance(this@MainActivity).sightingDao().clearAll()
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        scope.cancel()
    }
}
