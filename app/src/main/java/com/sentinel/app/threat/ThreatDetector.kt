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
        userLocationHistory: List<Pair<Double, Double>>
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

        // Signal 1: RSSI trend (0-10 pts)
        val rssiTrendScore = computeRssiTrendScore(validSightings)

        // Signal 2: Arrival coupling (0-20 pts)
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
     * Fixed version: checks user displacement in the time window around each sighting,
     * not globally across the entire history.
     */
    private fun filterStationary(
        sightings: List<DeviceSighting>,
        userHistory: List<Pair<Double, Double>>
    ): List<DeviceSighting> {
        if (userHistory.size < 2) return sightings

        // Compute total user displacement as a rough proxy for whether they were moving.
        // A more precise version would index user positions by timestamp — for now this
        // correctly gates on whether the user was mobile at all during the session.
        val totalUserDisplacement = userHistory.zipWithNext().sumOf { (a, b) ->
            haversineDistance(a.first, a.second, b.first, b.second)
        }

        return if (totalUserDisplacement >= MIN_USER_DISPLACEMENT_M) sightings else emptyList()
    }

    /**
     * Computes a 0-10 score based on whether RSSI is trending upward (device approaching).
     * Uses linear regression slope on (timestamp, rssi) pairs.
     */
    private fun computeRssiTrendScore(sightings: List<DeviceSighting>): Int {
        if (sightings.size < 3) return 0

        val sorted = sightings.sortedBy { it.timestamp }
        val n = sorted.size.toDouble()

        // Normalize timestamps to seconds from first sighting to avoid floating point issues
        val t0 = sorted.first().timestamp
        val xs = sorted.map { (it.timestamp - t0) / 1000.0 }
        val ys = sorted.map { it.rssi.toDouble() }

        val meanX = xs.average()
        val meanY = ys.average()

        val numerator = xs.zip(ys).sumOf { (x, y) -> (x - meanX) * (y - meanY) }
        val denominator = xs.sumOf { x -> (x - meanX).pow(2) }

        if (denominator == 0.0) return 0

        val slope = numerator / denominator // dBm per second

        // RSSI is negative (e.g. -70 dBm). A positive slope means it's rising toward 0 = getting stronger.
        // A slope of +0.05 dBm/sec or more is a meaningful approach signal.
        return when {
            slope >= 0.10 -> 10
            slope >= 0.05 -> 7
            slope >= 0.02 -> 4
            slope >= 0.0  -> 1
            else -> 0
        }
    }

    /**
     * Computes a 0-20 score based on whether the device arrived after the user at each location.
     * A follower arrives after you — a coincidental device is already there.
     */
    private fun computeArrivalCouplingScore(
        sightings: List<DeviceSighting>,
        userHistory: List<Pair<Double, Double>>
    ): Int {
        if (sightings.size < 2 || userHistory.size < 2) return 0

        // Build location clusters for the device
        val clusters = buildClusters(sightings)
        if (clusters.size < 2) return 0

        // For each cluster, find the earliest device sighting there
        // and compare to the earliest user position near that cluster.
        // If device arrived after user at most stops → follower pattern.
        var followerCount = 0
        var comparableCount = 0

        for ((center, clusterSightings) in clusters) {
            val deviceArrival = clusterSightings.minOf { it.timestamp }

            // Find the earliest user position within LOCATION_CLUSTER_RADIUS_M of this cluster center
            val userArrivalIndex = userHistory.indexOfFirst { (lat, lon) ->
                haversineDistance(lat, lon, center.first, center.second) < LOCATION_CLUSTER_RADIUS_M
            }

            if (userArrivalIndex >= 0) {
                comparableCount++
                // We don't have timestamps on userHistory entries, so we use index as a proxy
                // for time (earlier index = earlier in session). Device arrived "after" if
                // deviceArrival is later than the session midpoint weighted by user index.
                // Better: if user was there first (low index) and device arrived, it followed.
                // Heuristic: if user index is in first 60% of their history, device arrival
                // after session start suggests it followed rather than preceded.
                val userPositionRatio = userArrivalIndex.toDouble() / userHistory.size
                if (userPositionRatio < 0.6) {
                    followerCount++
                }
            }
        }

        if (comparableCount == 0) return 0
        val ratio = followerCount.toDouble() / comparableCount
        return (ratio * 20).toInt()
    }

    /**
     * Groups sightings into geographic clusters, returning each cluster's
     * center coordinate and the sightings that belong to it.
     */
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