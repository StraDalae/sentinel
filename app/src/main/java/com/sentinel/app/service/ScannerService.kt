package com.sentinel.app.service

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.bluetooth.BluetoothManager
import android.bluetooth.le.BluetoothLeScanner
import android.bluetooth.le.ScanCallback
import android.bluetooth.le.ScanResult
import android.bluetooth.le.ScanSettings
import android.content.Intent
import android.content.pm.ServiceInfo
import android.location.Location
import android.os.Binder
import android.os.Build
import android.os.IBinder
import androidx.core.app.NotificationCompat
import com.google.android.gms.location.*
import com.sentinel.app.MainActivity
import com.sentinel.app.R
import com.sentinel.app.db.AppDatabase
import com.sentinel.app.model.DeviceSighting
import com.sentinel.app.threat.ThreatDetector
import kotlinx.coroutines.*
import java.security.MessageDigest
import java.util.ArrayDeque
import kotlin.math.abs

class ScannerService : Service() {

    inner class LocalBinder : Binder() {
        fun getService(): ScannerService = this@ScannerService
    }

    private val binder = LocalBinder()
    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())

    private var bluetoothLeScanner: BluetoothLeScanner? = null
    private var fusedLocationClient: FusedLocationProviderClient? = null
    private lateinit var threatDetector: ThreatDetector

    var isScanning = false
        private set

    private val userLocationHistory = ArrayDeque<Pair<Long, Pair<Double, Double>>>(50)
    private val alertedFingerprints = mutableSetOf<String>()

    /**
     * Identity info for a device currently believed to be nearby, keyed by fingerprint.
     * advertisedKey is the stable payload-derived key used for this fingerprint, or null
     * if this fingerprint was assigned purely from a MAC address (no stable payload found).
     */
    private data class LiveDevice(
        val fingerprint: String,
        val lastSeen: Long,
        val lastRssi: Int,
        val advertisedKey: String?
    )

    private val liveDevices = mutableMapOf<String, LiveDevice>()

    /**
     * Devices that recently dropped out of range. Held for ROTATION_GRACE_MS so that if a
     * MAC-only device (no stable advertised payload) reappears under a new rotated address
     * with a similar signal strength, we can bridge it back to the same fingerprint instead
     * of minting a new one. Best-effort heuristic — not a cryptographic guarantee.
     */
    private val vanishedDevices = mutableListOf<LiveDevice>()

    private var pruneJob: Job? = null

    val recentSightings = mutableMapOf<String, DeviceSighting>()

    var currentLocation: Location? = null
        private set

    var onNewSighting: ((DeviceSighting) -> Unit)? = null
    var onNearbyCountChanged: ((Int) -> Unit)? = null
    var onDeviceVanished: ((String) -> Unit)? = null

    companion object {
        const val CHANNEL_ID = "sentinel_scan"
        const val NOTIF_ID_SERVICE = 1
        const val NOTIF_ID_THREAT = 2
        const val ACTION_START = "ACTION_START"
        const val ACTION_STOP = "ACTION_STOP"

        // How long a device can go unseen before we consider it gone.
        private const val STALE_TIMEOUT_MS = 30_000L
        // How often we sweep for stale devices.
        private const val PRUNE_INTERVAL_MS = 10_000L
        // How long a vanished MAC-only device stays eligible for rotation-bridging.
        private const val ROTATION_GRACE_MS = 3 * 60_000L
        // How close two RSSI readings must be to be considered "probably the same radio".
        private const val RSSI_BRIDGE_TOLERANCE = 12
    }

    private val locationCallback = object : LocationCallback() {
        override fun onLocationResult(result: LocationResult) {
            val loc = result.lastLocation ?: return
            currentLocation = loc
            if (userLocationHistory.size >= 50) userLocationHistory.removeFirst()
            userLocationHistory.add(Pair(System.currentTimeMillis(), Pair(loc.latitude, loc.longitude)))
        }
    }

    private val leScanCallback = object : ScanCallback() {
        override fun onScanResult(callbackType: Int, result: ScanResult) {
            handleScanResult(result)
        }
        override fun onBatchScanResults(results: List<ScanResult>) {
            results.forEach { handleScanResult(it) }
        }
        override fun onScanFailed(errorCode: Int) {
            isScanning = false
        }
    }

    override fun onCreate() {
        super.onCreate()
        val db = AppDatabase.getInstance(this)
        threatDetector = ThreatDetector(db)

        val bluetoothManager = getSystemService(BLUETOOTH_SERVICE) as BluetoothManager
        bluetoothLeScanner = bluetoothManager.adapter.bluetoothLeScanner
        fusedLocationClient = LocationServices.getFusedLocationProviderClient(this)

        createNotificationChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_START -> startScanning()
            ACTION_STOP -> stopScanning()
        }
        return START_STICKY
    }

    private fun startScanning() {
        if (isScanning) return
        isScanning = true

        val notification = createServiceNotification("Sentinel is active", "Scanning for suspicious devices...")

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            var type = ServiceInfo.FOREGROUND_SERVICE_TYPE_LOCATION
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                type = type or ServiceInfo.FOREGROUND_SERVICE_TYPE_CONNECTED_DEVICE
            }
            startForeground(NOTIF_ID_SERVICE, notification, type)
        } else {
            startForeground(NOTIF_ID_SERVICE, notification)
        }

        // Request location updates
        val locationRequest = LocationRequest.Builder(Priority.PRIORITY_HIGH_ACCURACY, 10000)
            .setMinUpdateIntervalMillis(5000)
            .build()

        try {
            fusedLocationClient?.requestLocationUpdates(locationRequest, locationCallback, null)

            val settings = ScanSettings.Builder()
                .setScanMode(ScanSettings.SCAN_MODE_LOW_LATENCY)
                .build()
            bluetoothLeScanner?.startScan(null, settings, leScanCallback)

            pruneJob?.cancel()
            pruneJob = scope.launch {
                while (isActive) {
                    delay(PRUNE_INTERVAL_MS)
                    pruneStaleDevices()
                }
            }
        } catch (e: SecurityException) {
            isScanning = false
        }
    }

    private fun stopScanning() {
        isScanning = false
        try {
            bluetoothLeScanner?.stopScan(leScanCallback)
        } catch (e: SecurityException) {}
        fusedLocationClient?.removeLocationUpdates(locationCallback)
        pruneJob?.cancel()
        pruneJob = null
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    fun clearSession() {
        recentSightings.clear()
        alertedFingerprints.clear()
        liveDevices.clear()
        vanishedDevices.clear()
        onNearbyCountChanged?.invoke(0)
    }

    // ── Device identity resolution ──────────────────────────────────────────

    /**
     * Pulls a stable, per-unit identifier out of the advertisement payload, if one exists.
     * Many BLE accessories (trackers, headphones, fitness bands, iBeacon/Eddystone-style
     * beacons) include a persistent ID in manufacturer or service data that does NOT rotate
     * when the device's Bluetooth MAC address does. Returns null if nothing usable is present
     * (common for plain phones, which only advertise generic/empty payloads).
     */
    private fun buildAdvertisedKey(result: ScanResult): String? {
        val record = result.scanRecord ?: return null

        val mfgData = record.manufacturerSpecificData
        if (mfgData != null && mfgData.size() > 0) {
            val id = mfgData.keyAt(0)
            val bytes = mfgData.valueAt(0)
            if (bytes != null && bytes.isNotEmpty()) {
                return "mfg:$id:" + bytes.joinToString("") { "%02x".format(it) }
            }
        }

        val serviceData = record.serviceData
        if (serviceData != null && serviceData.isNotEmpty()) {
            val entry = serviceData.entries.first()
            if (entry.value.isNotEmpty()) {
                return "svc:${entry.key}:" + entry.value.joinToString("") { "%02x".format(it) }
            }
        }

        return null
    }

    private fun hash(input: String): String {
        val digest = MessageDigest.getInstance("SHA-256").digest(input.toByteArray())
        return digest.joinToString("") { "%02x".format(it) }.take(16)
    }

    /**
     * Resolves a scan result to a device fingerprint that's stable across MAC rotation
     * where possible. Returns the fingerprint plus the advertisedKey used (or null).
     */
    private fun resolveFingerprint(result: ScanResult, rssi: Int, now: Long): Pair<String, String?> {
        val advertisedKey = buildAdvertisedKey(result)
        if (advertisedKey != null) {
            return "adv:" + hash(advertisedKey) to advertisedKey
        }

        // No stable payload — this device only exposes a rotating private MAC. Try to
        // bridge it to a device that just vanished with a similar signal strength rather
        // than minting a new identity for what's likely the same radio.
        val bridgeMatch = vanishedDevices.firstOrNull {
            it.advertisedKey == null &&
                (now - it.lastSeen) <= ROTATION_GRACE_MS &&
                abs(it.lastRssi - rssi) <= RSSI_BRIDGE_TOLERANCE
        }
        if (bridgeMatch != null) {
            vanishedDevices.remove(bridgeMatch)
            return bridgeMatch.fingerprint to null
        }

        return ("mac:" + result.device.address) to null
    }

    private fun handleScanResult(result: ScanResult) {
        val rssi = result.rssi
        val timestamp = System.currentTimeMillis()
        val loc = currentLocation ?: return

        val (fingerprint, advertisedKey) = resolveFingerprint(result, rssi, timestamp)

        liveDevices[fingerprint] = LiveDevice(
            fingerprint = fingerprint,
            lastSeen = timestamp,
            lastRssi = rssi,
            advertisedKey = advertisedKey
        )

        val sighting = DeviceSighting(
            deviceFingerprint = fingerprint,
            rawMac = result.device.address,
            rssi = rssi,
            timestamp = timestamp,
            latitude = loc.latitude,
            longitude = loc.longitude,
            seenAtLocations = 1
        )

        recentSightings[fingerprint] = sighting
        onNewSighting?.invoke(sighting)
        onNearbyCountChanged?.invoke(recentSightings.size)

        scope.launch {
            val updatedSighting = threatDetector.processSighting(sighting, userLocationHistory.toList())
            if (updatedSighting.threatScore >= ThreatDetector.SCORE_ALERT_THRESHOLD && !alertedFingerprints.contains(fingerprint)) {
                alertedFingerprints.add(fingerprint)
                showThreatNotification(updatedSighting)
            }
        }
    }

    /** Removes devices we haven't heard from in STALE_TIMEOUT_MS from the "nearby" set. */
    private fun pruneStaleDevices() {
        val now = System.currentTimeMillis()
        val stale = liveDevices.values.filter { now - it.lastSeen > STALE_TIMEOUT_MS }
        if (stale.isNotEmpty()) {
            stale.forEach { device ->
                liveDevices.remove(device.fingerprint)
                recentSightings.remove(device.fingerprint)
                vanishedDevices.add(device)
                onDeviceVanished?.invoke(device.fingerprint)
            }
            onNearbyCountChanged?.invoke(recentSightings.size)
        }

        // Bound the bridging window's memory use.
        vanishedDevices.removeAll { now - it.lastSeen > ROTATION_GRACE_MS }
    }

    private fun createNotificationChannel() {
        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                "Sentinel Scanner",
                NotificationManager.IMPORTANCE_LOW
            )
            val manager = getSystemService(NotificationManager::class.java)
            manager.createNotificationChannel(channel)
        }
    }

    private fun createServiceNotification(title: String, content: String): Notification {
        val pendingIntent = PendingIntent.getActivity(
            this, 0, Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE
        )

        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle(title)
            .setContentText(content)
            .setSmallIcon(android.R.drawable.ic_dialog_info)
            .setContentIntent(pendingIntent)
            .setOngoing(true)
            .build()
    }

    private fun showThreatNotification(sighting: DeviceSighting) {
        val notificationManager = getSystemService(NotificationManager::class.java)
        val notification = NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("Suspicious Device Detected")
            .setContentText("A device has been following you across multiple locations.")
            .setSmallIcon(android.R.drawable.stat_sys_warning)
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .build()

        notificationManager.notify(NOTIF_ID_THREAT, notification)
    }

    override fun onBind(intent: Intent?): IBinder = binder

    override fun onDestroy() {
        super.onDestroy()
        scope.cancel()
    }
}