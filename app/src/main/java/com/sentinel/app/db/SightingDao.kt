package com.sentinel.app.db

import androidx.room.*
import com.sentinel.app.model.DeviceSighting

@Dao
interface SightingDao {

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insert(sighting: DeviceSighting)

    @Update
    suspend fun update(sighting: DeviceSighting)

    @Query("SELECT * FROM device_sightings WHERE timestamp > :since ORDER BY timestamp DESC")
    suspend fun getRecentSightings(since: Long): List<DeviceSighting>

    @Query("SELECT * FROM device_sightings WHERE deviceFingerprint = :fingerprint AND timestamp > :since ORDER BY timestamp ASC")
    suspend fun getSightingsForDevice(fingerprint: String, since: Long): List<DeviceSighting>

    @Query("DELETE FROM device_sightings WHERE timestamp < :before")
    suspend fun deleteOlderThan(before: Long)

    @Query("DELETE FROM device_sightings")
    suspend fun clearAll()

    @Query("SELECT * FROM device_sightings WHERE seenAtLocations >= 3 ORDER BY seenAtLocations DESC")
    suspend fun getThreats(): List<DeviceSighting>
}
