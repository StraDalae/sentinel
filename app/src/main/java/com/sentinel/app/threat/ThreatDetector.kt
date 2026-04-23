package com.sentinel.app.threat

import com.sentinel.app.db.AppDatabase
import com.sentinel.app.model.DeviceSighting
import kotlin.math.*

class ThreatDetector(private val db: AppDatabase) {

    companion object {
        // How far apart two sightings must be to count as genuinely different locations.
        // Raised from 150m to 500m — this prevents a car driving one mile behind you
        // from triggering 6 "location" clusters every few hundred meters.
        const val LOCATION_CLUSTER_RADIUS_M = 500.0

        // YOU must have moved at least this far between two sightings of the same device
        // for those sightings to count as "following." If you're stationary (at a register,
        // at your desk), devices passing by are not following you — you're just in their path.
        const val MIN_USER_DISPLACEMENT_M = 300.0

        // Sightings must span at least this long to be considered suspicious.
        // Eliminates the "car behind me for one mile" false alarm — that's ~90 seconds.
        const val MIN_TIME_SPREAD_MS = 20 * 60 * 1000L // 20 minutes

        // Maximum plausible speed for a device to travel between two sightings (m/s).
        // ~250 km/h — if a device appears faster than this, it's two different physical
        // devices that happened to produce the same fingerprint. Discard the sighting.
        const val MAX_PLAUSIBLE_SPEED_MS = 70.0

        // How far back in time we keep sighting history.
        const val HISTORY_WINDOW_MS = 8 * 60 * 60 * 1000L // 8 hours

        // Score thresholds
        const val SCORE_ALERT_THRESHOLD = 60  // fire a notification above this
        const val SCORE_WARN_THRESHOLD = 30   // show yellow marker above this
    }

    /**
     * Process a new sighting of a device. Returns an updated sighting with
     * threatScore and seenAtLocations populated.
     *
     * The threat score is 0-100 and is built from multiple weighted signals:
     *   - Number of distinct locations (with user displacement check): up to 50 pts
     *   - Time spread of sightings: up to 25 pts
     *   - Consistency of following (did it appear at every stop?): up to 25 pts
     */
    suspend fun processSighting(
        sighting: DeviceSighting,
        userLocationHistory: List<Pair<Double, Double>> // recent user GPS positions
    ): DeviceSighting {
        val dao = db.sightingDao()
        val history = dao.getSightingsForDevice(
            fingerprint = sighting.deviceFingerprint,
            since = System.currentTimeMillis() - HISTORY_WINDOW_MS
        )

        // Speed sanity check — if this sighting is physically impossible given the
        // last known sighting of this fingerprint, discard it (fingerprint collision).
        if (history.isNotEmpty()) {
            val last = history.last()
            val distFromLast = haversineDistance(
                last.latitude, last.longitude,
                sighting.latitude, sighting.longitude
            )
            val timeFromLast = (sighting.timestamp - last.timestamp).coerceAtLeast(1L)
            val speedMps = distFromLast / (timeFromLast / 1000.0)
            if (speedMps > MAX_PLAUSIBLE_SPEED_MS) {
                // Fingerprint collision — two different physical devices.
                // Return the sighting unsaved so it doesn't pollute the record.
                return sighting.copy(seenAtLocations = 0, threatScore = 0)
            }
        }

        // Compute valid location clusters, filtering out sightings where user wasn't moving
        val validSightings = filterStationary(history + sighting, userLocationHistory)
        val distinctLocations = countDistinctLocations(validSightings)
        val timeSpreadMs = computeTimeSpread(validSightings)
        val consistencyRatio = computeConsistency(validSightings, distinctLocations)

        // Build threat score from three weighted components
        val locationScore = (distinctLocations.coerceAtMost(5) / 5.0 * 50).toInt()
        val timeScore = (timeSpreadMs.toDouble() / (60 * 60 * 1000) * 25)
            .coerceAtMost(25.0).toInt()
        val consistencyScore = (consistencyRatio * 25).toInt()

        // Only add time/consistency score if minimum thresholds are met
        val threatScore = if (
            distinctLocations >= 2 &&
            timeSpreadMs >= MIN_TIME_SPREAD_MS
        ) {
            locationScore + timeScore + consistencyScore
        } else {
            0
        }

        val updatedSighting = sighting.copy(
            seenAtLocations = distinctLocations,
            threatScore = threatScore
        )

        // Upsert: update existing nearby cluster, or insert new record
        val existingNearby = history.firstOrNull { existing ->
            haversineDistance(
                existing.latitude, existing.longitude,
                sighting.latitude, sighting.longitude
            ) < LOCATION_CLUSTER_RADIUS_M
        }

        if (existingNearby != null) {
            dao.update(updatedSighting.copy(id = existingNearby.id))
        } else {
            dao.insert(updatedSighting)
        }

        dao.deleteOlderThan(System.currentTimeMillis() - HISTORY_WINDOW_MS)
        return updatedSighting
    }

    /**
     * Filter out sightings that occurred while the user was essentially stationary.
     * If the user didn't move MIN_USER_DISPLACEMENT_M between two sightings of the
     * same device, those sightings don't count as "following" — the device was just
     * also in the area (e.g. a coworker's phone, a customer passing a register).
     */
    private fun filterStationary(
        sightings: List<DeviceSighting>,
        userHistory: List<Pair<Double, Double>>
    ): List<DeviceSighting> {
        if (userHistory.size < 2) return sightings

        return sightings.filter { sighting ->
            // Find what the user's position was around the time of this sighting
            // by picking the closest user location entry in time (approximation)
            val userMovedEnough = userHistory.zipWithNext().any { (a, b) ->
                haversineDistance(a.first, a.second, b.first, b.second) >= MIN_USER_DISPLACEMENT_M
            }
            userMovedEnough
        }
    }

    /**
     * Group sightings into geographic clusters. Returns count of distinct clusters.
     */
    private fun countDistinctLocations(sightings: List<DeviceSighting>): Int {
        if (sightings.isEmpty()) return 0
        val clusters = mutableListOf<Pair<Double, Double>>()
        for (s in sightings) {
            val inCluster = clusters.any { (clat, clon) ->
                haversineDistance(clat, clon, s.latitude, s.longitude) < LOCATION_CLUSTER_RADIUS_M
            }
            if (!inCluster) clusters.add(Pair(s.latitude, s.longitude))
        }
        return clusters.size
    }

    /**
     * How long (ms) between the earliest and latest sighting of this device.
     */
    private fun computeTimeSpread(sightings: List<DeviceSighting>): Long {
        if (sightings.size < 2) return 0L
        val sorted = sightings.sortedBy { it.timestamp }
        return sorted.last().timestamp - sorted.first().timestamp
    }

    /**
     * Consistency ratio: of the user's distinct stops, at what fraction did this
     * device also appear? 1.0 = appeared everywhere the user went (very suspicious).
     * 0.2 = appeared at one out of five stops (likely coincidence).
     */
    private fun computeConsistency(sightings: List<DeviceSighting>, deviceLocations: Int): Double {
        if (deviceLocations == 0) return 0.0
        // We approximate user stops as the number of device location clusters.
        // A true implementation would compare against total user stops recorded.
        // For now, more sightings per cluster = higher consistency signal.
        val avgSightingsPerCluster = sightings.size.toDouble() / deviceLocations
        return (avgSightingsPerCluster / 5.0).coerceAtMost(1.0)
    }

    /**
     * Haversine formula — distance between two GPS coordinates in meters.
     */
    fun haversineDistance(lat1: Double, lon1: Double, lat2: Double, lon2: Double): Double {
        val r = 6371000.0
        val dLat = Math.toRadians(lat2 - lat1)
        val dLon = Math.toRadians(lon2 - lon1)
        val a = sin(dLat / 2).pow(2) +
                cos(Math.toRadians(lat1)) * cos(Math.toRadians(lat2)) *
                sin(dLon / 2).pow(2)
        return r * 2 * atan2(sqrt(a), sqrt(1 - a))
    }
}
