package com.sentinel.app.model

import androidx.room.Entity
import androidx.room.PrimaryKey

@Entity(tableName = "device_sightings")
data class DeviceSighting(
    @PrimaryKey(autoGenerate = true) val id: Long = 0,
    val deviceFingerprint: String,
    val rawMac: String,
    val rssi: Int,
    val latitude: Double,
    val longitude: Double,
    val timestamp: Long,
    val seenAtLocations: Int,
    val threatScore: Int = 0   // 0-100. 0-29 = noise, 30-59 = watch, 60+ = alert
)
