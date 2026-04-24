package com.sentinel.app.service

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.bluetooth.BluetoothAdapter
import android.bluetooth.BluetoothManager
import android.bluetooth.le.BluetoothLeScanner
import android.bluetooth.le.ScanCallback
import android.bluetooth.le.ScanResult
import android.bluetooth.le.ScanSettings
import android.content.Intent
import android.location.Location
import android.os.Binder
import android.os.IBinder
import androidx.core.app.NotificationCompat
import com.google.android.gms.location.*
import com.sentinel.app.MainActivity
import com.sentinel.app.R
import com.sentinel.app.db.AppDatabase
import com.sentinel.app.model.DeviceSighting
import com.sentinel.app.threat.ThreatDetector
import kotlinx.coroutines.*

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

    val recentSightings = mutableMapOf<String, DeviceSighting>()

    var currentLocation: Location? = null
        private set

    var onNewSighting: ((DeviceSighting) -> Unit)? = null
    var onNearbyCountChanged: ((Int) -> Unit)? = null

    companion object {
        const val CHANNEL_ID = "sentinel_scan"
        const val NOTIF_ID_SERVICE = 1
        const val NOTIF_ID_THREAT = 2
        const val ACTION_START = "ACTION_START"
        const val ACTION_STOP = "ACTION_STOP"
    }

    private val locationCallback = object : LocationCallback() {
        override fun onLocationResult(result: LocationResult) {
            val loc = result.lastLocation ?: return
            currentLocation = loc
            if (userLocationHistory.size >= 50) userLocationHistory.removeFirst()
            userLocationHistory.addLast(Pair(System.currentTimeMillis(), Pair(loc.latitude, loc.longitude)))
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
        createNotificationChannel()
        threatDetector = ThreatDetector(AppDatabase.getInstance(this))
        setupLocationUpdates()
        startForeground(NOTIF_ID_SERVICE, buildServiceNotification())
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_START -> { if (!isScanning) startBLEScan() }
            ACTION_STOP  -> { stopBLEScan(); stopSelf() }
            else         -> { if (!isScanning) startBLEScan() }
        }
        return START_STICKY
    }

    override fun onBind(intent: Intent?): IBinder = binder
    override fun onRebind(intent: Intent?) = super.onRebind(intent)
    override fun onUnbind(intent: Intent?): Boolean = true

    /**
     * Called by MainActivity when the user hits Clear.
     * Wipes the in-memory cache so every device currently in range
     * gets treated as brand new on the next scan result — causing
     * their markers to reappear on the map immediately.
     * Does NOT stop the BLE scan.
     */
    fun clearSession() {
        recentSightings.clear()
        alertedFingerprints.clear()
        // Fire count update so the UI resets to 0 immediately
        scope.launch(Dispatchers.Main) {
            onNearbyCountChanged?.invoke(0)
        }
    }

    private fun setupLocationUpdates() {
        fusedLocationClient = LocationServices.getFusedLocationProviderClient(this)
        val request = LocationRequest.Builder(Priority.PRIORITY_HIGH_ACCURACY, 5000L)
            .setMinUpdateIntervalMillis(3000L).build()
        try {
            fusedLocationClient?.requestLocationUpdates(request, locationCallback, mainLooper)
        } catch (e: SecurityException) {}
    }

    private fun startBLEScan() {
        val adapter: BluetoothAdapter? =
            (getSystemService(BluetoothManager::class.java))?.adapter
        if (adapter == null || !adapter.isEnabled) return
        bluetoothLeScanner = adapter.bluetoothLeScanner
        val settings = ScanSettings.Builder()
            .setScanMode(ScanSettings.SCAN_MODE_BALANCED)
            .build()
        try {
            bluetoothLeScanner?.startScan(null, settings, leScanCallback)
            isScanning = true
        } catch (e: SecurityException) {
            isScanning = false
        }
    }

    private fun stopBLEScan() {
        try { bluetoothLeScanner?.stopScan(leScanCallback) } catch (e: SecurityException) {}
        isScanning = false
        recentSightings.clear()
        alertedFingerprints.clear()
    }

    private fun handleScanResult(result: ScanResult) {
        val location = currentLocation ?: return
        val fingerprint = buildFingerprint(result)

        // isNewDevice must be checked BEFORE updating recentSightings,
        // so a post-clear device is correctly treated as new.
        val isNewDevice = !recentSightings.containsKey(fingerprint)

        val sighting = DeviceSighting(
            deviceFingerprint = fingerprint,
            rawMac = result.device.address,
            rssi = result.rssi,
            latitude = location.latitude,
            longitude = location.longitude,
            timestamp = System.currentTimeMillis(),
            seenAtLocations = 0,
            threatScore = 0
        )

        scope.launch {
            val updated = threatDetector.processSighting(
                sighting = sighting,
                userLocationHistory = userLocationHistory.toList()
            )

            recentSightings[fingerprint] = updated

            // Fire count update for every new unique device —
            // after a clearSession() all nearby devices are "new" again
            if (isNewDevice) {
                withContext(Dispatchers.Main) {
                    onNearbyCountChanged?.invoke(recentSightings.size)
                }
            }

            if (updated.threatScore >= ThreatDetector.SCORE_ALERT_THRESHOLD &&
                !alertedFingerprints.contains(fingerprint)) {
                alertedFingerprints.add(fingerprint)
                fireThreatNotification(updated)
            }

            // Always fire onNewSighting — MainActivity uses this to place/update markers.
            // After a clear, isNewDevice=true means a fresh marker gets created.
            withContext(Dispatchers.Main) { onNewSighting?.invoke(updated) }
        }
    }

    private fun buildFingerprint(result: ScanResult): String {
        val sb = StringBuilder()
        result.scanRecord?.let { record ->
            sb.append(record.advertiseFlags)
            sb.append(record.txPowerLevel)
            record.serviceUuids?.forEach { sb.append(it.toString()) }
            record.bytes?.let { sb.append(it.take(10).hashCode()) }
        }
        sb.append(result.primaryPhy)
        sb.append(result.secondaryPhy)
        return if (sb.isEmpty()) result.device.address
        else sb.toString().hashCode().toString(16)
    }

    private fun fireThreatNotification(sighting: DeviceSighting) {
        val pendingIntent = PendingIntent.getActivity(
            this, 0, Intent(this, MainActivity::class.java), PendingIntent.FLAG_IMMUTABLE
        )
        val notification = NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_warning)
            .setContentTitle("⚠ Possible Stalking Device Detected")
            .setContentText(
                "Threat score ${sighting.threatScore}/100 · " +
                "Seen at ${sighting.seenAtLocations} locations."
            )
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setContentIntent(pendingIntent)
            .setAutoCancel(true)
            .setVibrate(longArrayOf(0, 500, 200, 500))
            .build()
        getSystemService(NotificationManager::class.java).notify(NOTIF_ID_THREAT, notification)
    }

    private fun buildServiceNotification(): Notification {
        val pendingIntent = PendingIntent.getActivity(
            this, 0, Intent(this, MainActivity::class.java), PendingIntent.FLAG_IMMUTABLE
        )
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_radar)
            .setContentTitle("Sentinel is active")
            .setContentText("Monitoring nearby devices...")
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .setContentIntent(pendingIntent)
            .build()
    }

    private fun createNotificationChannel() {
        val channel = NotificationChannel(
            CHANNEL_ID, "Sentinel Scanner", NotificationManager.IMPORTANCE_HIGH
        ).apply { description = "Sentinel background scanning and threat alerts" }
        getSystemService(NotificationManager::class.java).createNotificationChannel(channel)
    }

    override fun onDestroy() {
        super.onDestroy()
        stopBLEScan()
        fusedLocationClient?.removeLocationUpdates(locationCallback)
        scope.cancel()
    }
}
