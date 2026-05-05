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
import java.util.ArrayDeque

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
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    fun clearSession() {
        recentSightings.clear()
        alertedFingerprints.clear()
        onNearbyCountChanged?.invoke(0)
    }

    private fun handleScanResult(result: ScanResult) {
        val device = result.device
        val rssi = result.rssi
        val timestamp = System.currentTimeMillis()
        val loc = currentLocation ?: return

        val sighting = DeviceSighting(
            deviceFingerprint = device.address,
            rawMac = device.address,
            rssi = rssi,
            timestamp = timestamp,
            latitude = loc.latitude,
            longitude = loc.longitude,
            seenAtLocations = 1
        )

        recentSightings[device.address] = sighting
        onNewSighting?.invoke(sighting)
        onNearbyCountChanged?.invoke(recentSightings.size)

        scope.launch {
            val updatedSighting = threatDetector.processSighting(sighting, userLocationHistory.toList())
            if (updatedSighting.threatScore >= ThreatDetector.SCORE_ALERT_THRESHOLD && !alertedFingerprints.contains(device.address)) {
                alertedFingerprints.add(device.address)
                showThreatNotification(updatedSighting)
            }
        }
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
