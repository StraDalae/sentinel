package com.sentinel.app.threat

import com.sentinel.app.db.AppDatabase
import com.sentinel.app.model.DeviceSighting
import kotlin.math.*

class ThreatDetector(private val db: AppDatabase) {

    companion object {
        const val LOCATION_CLUSTER_RADIUS_M = 500.0
        const val MIN_USER_DISPLACEMENT_M = 300.0
        const val MIN_TIME_SPREAD_MS = 20 * 60 * 1000L
        const val MAX_PLAUSIBLE_SPEED_MS = 70.0
        const val HISTORY_WINDOW_MS = 8 * 60 * 60 * 1000L
        const val SCORE_ALERT_THRESHOLD = 60
        const val SCORE_WARN_THRESHOLD = 30
    }

    suspend fun processSighting(
        sighting: DeviceSighting,
        userLocationHistory: List<Pair<Long, Pair<Double, Double>>> // timestamp -> (lat, lon)
    ): DeviceSighting {
        val dao = db.sightingDao()
        val history = dao.getSightingsForDevice(
            fingerprint = sighting.deviceFingerprint,
            since = System.currentTimeMillis() - HISTORY_WINDOW_MS
        )

        // Speed sanity check
        if (history.isNotEmpty()) {
            val last = history.last()
            val distFromLast = haversineDistance(
                last.latitude, last.longitude,
                sighting.latitude, sighting.longitude
            )
            val timeFromLast = (sighting.timestamp - last.timestamp).coerceAtLeast(1L)
            val speedMps = distFromLast / (timeFromLast / 1000.0)
            if (speedMps > MAX_PLAUSIBLE_SPEED_MS) {
                return sighting.copy(seenAtLocations = 0, threatScore = 0)
            }
        }

        val allSightings = history + sighting
        val validSightings = filterStationary(allSightings, userLocationHistory)
        val distinctLocations = countDistinctLocations(validSightings)
        val timeSpreadMs = computeTimeSpread(validSightings)
        val consistencyRatio = computeConsistency(validSightings, distinctLocations)
        val rssiTrendScore = computeRssiTrendScore(validSightings)
        val arrivalScore = computeArrivalCouplingScore(validSightings, userLocationHistory)

        val locationScore = (distinctLocations.coerceAtMost(3) / 3.0 * 45).toInt()
        val timeScore = (timeSpreadMs.toDouble() / (60 * 60 * 1000) * 15)
            .coerceAtMost(15.0).toInt()
        val consistencyScore = (consistencyRatio * 10).toInt()

        val threatScore = if (
            distinctLocations >= 2 &&
            timeSpreadMs >= MIN_TIME_SPREAD_MS
        ) {
            (locationScore + timeScore + consistencyScore + rssiTrendScore + arrivalScore)
                .coerceAtMost(100)
        } else {
            0
        }

        val updatedSighting = sighting.copy(
            seenAtLocations = distinctLocations,
            threatScore = threatScore
        )

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
     * Filters out sightings where the user wasn't meaningfully moving.
     * Now uses timestamps to check displacement only within the window
     * surrounding each sighting, rather than globally.
     */
    private fun filterStationary(
        sightings: List<DeviceSighting>,
        userHistory: List<Pair<Long, Pair<Double, Double>>>
    ): List<DeviceSighting> {
        if (userHistory.size < 2) return sightings

        return sightings.filter { sighting ->
            // Find user positions within a 5-minute window around this sighting
            val windowStart = sighting.timestamp - 5 * 60 * 1000L
            val windowEnd = sighting.timestamp + 5 * 60 * 1000L
            val windowPositions = userHistory
                .filter { (ts, _) -> ts in windowStart..windowEnd }
                .map { (_, pos) -> pos }

            if (windowPositions.size < 2) {
                // No window data — fall back to checking global displacement
                val totalDisplacement = userHistory.zipWithNext().sumOf { (a, b) ->
                    haversineDistance(a.second.first, a.second.second, b.second.first, b.second.second)
                }
                totalDisplacement >= MIN_USER_DISPLACEMENT_M
            } else {
                val windowDisplacement = windowPositions.zipWithNext().sumOf { (a, b) ->
                    haversineDistance(a.first, a.second, b.first, b.second)
                }
                windowDisplacement >= MIN_USER_DISPLACEMENT_M
            }
        }
    }

    /**
     * 0-10 pts. Positive RSSI slope = device is physically approaching.
     */
    private fun computeRssiTrendScore(sightings: List<DeviceSighting>): Int {
        if (sightings.size < 3) return 0

        val sorted = sightings.sortedBy { it.timestamp }
        val t0 = sorted.first().timestamp
        val xs = sorted.map { (it.timestamp - t0) / 1000.0 }
        val ys = sorted.map { it.rssi.toDouble() }

        val meanX = xs.average()
        val meanY = ys.average()
        val numerator = xs.zip(ys).sumOf { (x, y) -> (x - meanX) * (y - meanY) }
        val denominator = xs.sumOf { x -> (x - meanX).pow(2) }
        if (denominator == 0.0) return 0

        val slope = numerator / denominator
        return when {
            slope >= 0.10 -> 10
            slope >= 0.05 -> 7
            slope >= 0.02 -> 4
            slope >= 0.0  -> 1
            else          -> 0
        }
    }

    /**
     * 0-20 pts. Checks whether the device arrived after the user at each location cluster.
     * Uses real timestamps now that userLocationHistory carries them.
     */
    private fun computeArrivalCouplingScore(
        sightings: List<DeviceSighting>,
        userHistory: List<Pair<Long, Pair<Double, Double>>>
    ): Int {
        if (sightings.size < 2 || userHistory.size < 2) return 0

        val clusters = buildClusters(sightings)
        if (clusters.size < 2) return 0

        var followerCount = 0
        var comparableCount = 0

        for ((center, clusterSightings) in clusters) {
            val deviceArrival = clusterSightings.minOf { it.timestamp }

            // Find the earliest time the user was near this cluster
            val userArrival = userHistory
                .filter { (_, pos) ->
                    haversineDistance(pos.first, pos.second, center.first, center.second) < LOCATION_CLUSTER_RADIUS_M
                }
                .minOfOrNull { (ts, _) -> ts }

            if (userArrival != null) {
                comparableCount++
                // Device arrived after user = follower pattern
                if (deviceArrival > userArrival) {
                    followerCount++
                }
            }
        }

        if (comparableCount == 0) return 0
        val ratio = followerCount.toDouble() / comparableCount
        return (ratio * 20).toInt()
    }

    private fun buildClusters(sightings: List<DeviceSighting>): List<Pair<Pair<Double, Double>, List<DeviceSighting>>> {
        val clusters = mutableListOf<Pair<Pair<Double, Double>, MutableList<DeviceSighting>>>()
        for (s in sightings) {
            val existing = clusters.firstOrNull { (center, _) ->
                haversineDistance(center.first, center.second, s.latitude, s.longitude) < LOCATION_CLUSTER_RADIUS_M
            }
            if (existing != null) {
                existing.second.add(s)
            } else {
                clusters.add(Pair(Pair(s.latitude, s.longitude), mutableListOf(s)))
            }
        }
        return clusters
    }

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

    private fun computeTimeSpread(sightings: List<DeviceSighting>): Long {
        if (sightings.size < 2) return 0L
        val sorted = sightings.sortedBy { it.timestamp }
        return sorted.last().timestamp - sorted.first().timestamp
    }

    private fun computeConsistency(sightings: List<DeviceSighting>, deviceLocations: Int): Double {
        if (deviceLocations == 0) return 0.0
        val avgSightingsPerCluster = sightings.size.toDouble() / deviceLocations
        return (avgSightingsPerCluster / 5.0).coerceAtMost(1.0)
    }

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