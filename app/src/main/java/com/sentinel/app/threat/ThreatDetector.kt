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

        // Route mirroring constants
        const val MIN_BEARING_CHANGE_DEG = 45.0      // minimum turn angle to count as a decision point
        const val GPS_SUB_TURN_THRESHOLD_DEG = 25.0  // minimum sub-turn in raw GPS to count as complexity
        const val MIN_DECISION_POINTS = 2            // don't score mirroring until at least 2 real turns
        const val DEVICE_PRESENCE_WINDOW_MS = 3 * 60 * 1000L // how close in time a device sighting must be to count as "present" at a cluster
        const val MIN_GPS_POINTS_FOR_COMPLEXITY = 5  // minimum GPS points between clusters to use complexity factor
    }

    suspend fun processSighting(
        sighting: DeviceSighting,
        userLocationHistory: List<Pair<Long, Pair<Double, Double>>>
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
        val routeMirroringScore = computeRouteMirroringScore(validSightings, userLocationHistory)

        val locationScore = (distinctLocations.coerceAtMost(3) / 3.0 * 45).toInt()
        val timeScore = (timeSpreadMs.toDouble() / (60 * 60 * 1000) * 15)
            .coerceAtMost(15.0).toInt()
        val consistencyScore = (consistencyRatio * 10).toInt()

        val threatScore = if (
            distinctLocations >= 2 &&
            timeSpreadMs >= MIN_TIME_SPREAD_MS
        ) {
            (locationScore + timeScore + consistencyScore +
                    rssiTrendScore + arrivalScore + routeMirroringScore)
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

    // -------------------------------------------------------------------------
    // Route Mirroring (0-25 pts)
    // -------------------------------------------------------------------------

    /**
     * Scores how suspicious it is that this device followed the user's specific path.
     *
     * Approach:
     * 1. Build ordered user clusters from location history
     * 2. For each consecutive cluster pair, compute a surprisingness weight:
     *      - Base: bearing change between cluster centers
     *      - Modifier: path complexity from raw GPS points between clusters
     * 3. For each transition, check whether the device was present at the
     *    destination cluster within DEVICE_PRESENCE_WINDOW_MS of the user's arrival
     * 4. Score = weighted sum of present transitions / total weight, scaled to 0-25
     *    Only activates after MIN_DECISION_POINTS qualifying turns
     */
    private fun computeRouteMirroringScore(
        sightings: List<DeviceSighting>,
        userHistory: List<Pair<Long, Pair<Double, Double>>>
    ): Int {
        if (userHistory.size < MIN_GPS_POINTS_FOR_COMPLEXITY) return 0
        if (sightings.size < 2) return 0

        val userClusters = buildUserClusters(userHistory)
        if (userClusters.size < 3) return 0

        // For each cluster transition, compute surprisingness and check device presence
        var totalWeight = 0.0
        var mirroredWeight = 0.0
        var qualifyingDecisionPoints = 0

        for (i in 0 until userClusters.size - 1) {
            val fromCluster = userClusters[i]
            val toCluster = userClusters[i + 1]

            // Base bearing change between cluster centers
            val baseBearing = bearingChangeBetweenClusters(fromCluster, toCluster)

            // Only count this as a decision point if the turn is meaningful
            if (baseBearing < MIN_BEARING_CHANGE_DEG) continue
            qualifyingDecisionPoints++

            // GPS complexity factor for this segment
            val complexityFactor = computeSegmentComplexity(
                fromCluster, toCluster, userHistory
            )

            // Surprisingness = bearing sharpness * path complexity
            // Normalized so a 90-degree turn with complexity 1.0 = weight 1.0
            val surprisingness = (baseBearing / 90.0).coerceAtMost(1.0) * complexityFactor
            totalWeight += surprisingness

            // Check if device was present at the destination cluster
            // within the time window of the user's arrival there
            val userArrivalAtDest = toCluster.entries.minOf { it.key }
            val devicePresentAtDest = sightings.any { s ->
                haversineDistance(
                    s.latitude, s.longitude,
                    toCluster.centerLat, toCluster.centerLon
                ) < LOCATION_CLUSTER_RADIUS_M &&
                abs(s.timestamp - userArrivalAtDest) <= DEVICE_PRESENCE_WINDOW_MS
            }

            if (devicePresentAtDest) {
                mirroredWeight += surprisingness
            }
        }

        if (qualifyingDecisionPoints < MIN_DECISION_POINTS) return 0
        if (totalWeight == 0.0) return 0

        val mirroringRatio = mirroredWeight / totalWeight
        return (mirroringRatio * 25).toInt()
    }

    /**
     * Builds an ordered list of geographic clusters from the user's raw GPS history.
     * Each cluster captures its center, the GPS entries within it (timestamp -> position),
     * and the order in which the user visited it.
     */
    private fun buildUserClusters(
        userHistory: List<Pair<Long, Pair<Double, Double>>>
    ): List<UserCluster> {
        val clusters = mutableListOf<UserCluster>()

        for ((timestamp, pos) in userHistory) {
            val existing = clusters.firstOrNull { cluster ->
                haversineDistance(
                    cluster.centerLat, cluster.centerLon,
                    pos.first, pos.second
                ) < LOCATION_CLUSTER_RADIUS_M
            }
            if (existing != null) {
                existing.entries[timestamp] = pos
                // Update center as running average
                val n = existing.entries.size.toDouble()
                existing.centerLat = existing.entries.values.sumOf { it.first } / n
                existing.centerLon = existing.entries.values.sumOf { it.second } / n
            } else {
                val newCluster = UserCluster(
                    centerLat = pos.first,
                    centerLon = pos.second,
                    entries = mutableMapOf(timestamp to pos)
                )
                clusters.add(newCluster)
            }
        }

        return clusters
    }

    /**
     * Bearing change (degrees) between two cluster centers, relative to the
     * incoming direction of travel into fromCluster.
     * Returns 0-180 where 0 = straight ahead, 180 = U-turn.
     */
    private fun bearingChangeBetweenClusters(
        from: UserCluster,
        to: UserCluster
    ): Double {
        // Incoming bearing: direction the user was traveling to arrive at 'from'
        // We approximate this as the bearing from the earliest entry to the latest
        // entry within fromCluster — i.e. the direction of travel through it.
        val fromEntries = from.entries.entries.sortedBy { it.key }
        val incomingBearing = if (fromEntries.size >= 2) {
            val first = fromEntries.first().value
            val last = fromEntries.last().value
            computeBearing(first.first, first.second, last.first, last.second)
        } else {
            // Single point cluster — use center-to-center from previous if available
            computeBearing(from.centerLat, from.centerLon, to.centerLat, to.centerLon)
        }

        // Outgoing bearing: direction from fromCluster center to toCluster center
        val outgoingBearing = computeBearing(
            from.centerLat, from.centerLon,
            to.centerLat, to.centerLon
        )

        return abs(bearingDelta(incomingBearing, outgoingBearing))
    }

    /**
     * Computes a complexity multiplier (0.5 - 2.0) for the GPS path between two clusters.
     *
     * A straight line = 1.0 (no modifier).
     * A winding path with multiple sub-turns = up to 2.0 (more surprising to follow).
     * A path that contradicts the cluster-to-cluster bearing = down toward 0.5.
     */
    private fun computeSegmentComplexity(
        from: UserCluster,
        to: UserCluster,
        userHistory: List<Pair<Long, Pair<Double, Double>>>
    ): Double {
        // Extract GPS points that fall between the two clusters temporally
        val fromExit = from.entries.keys.max()
        val toArrival = to.entries.keys.min()

        val segmentPoints = userHistory
            .filter { (ts, _) -> ts in fromExit..toArrival }
            .map { (_, pos) -> pos }

        if (segmentPoints.size < MIN_GPS_POINTS_FOR_COMPLEXITY) return 1.0

        // Count sub-turns in the raw GPS stream
        var subTurnCount = 0
        for (j in 1 until segmentPoints.size - 1) {
            val b1 = computeBearing(
                segmentPoints[j - 1].first, segmentPoints[j - 1].second,
                segmentPoints[j].first, segmentPoints[j].second
            )
            val b2 = computeBearing(
                segmentPoints[j].first, segmentPoints[j].second,
                segmentPoints[j + 1].first, segmentPoints[j + 1].second
            )
            if (abs(bearingDelta(b1, b2)) >= GPS_SUB_TURN_THRESHOLD_DEG) {
                subTurnCount++
            }
        }

        // Complexity factor: each sub-turn adds 0.15, capped at 2.0, floored at 0.5
        return (1.0 + subTurnCount * 0.15).coerceIn(0.5, 2.0)
    }

    /**
     * Compass bearing in degrees (0-360) from point 1 to point 2.
     */
    private fun computeBearing(lat1: Double, lon1: Double, lat2: Double, lon2: Double): Double {
        val dLon = Math.toRadians(lon2 - lon1)
        val lat1R = Math.toRadians(lat1)
        val lat2R = Math.toRadians(lat2)
        val y = sin(dLon) * cos(lat2R)
        val x = cos(lat1R) * sin(lat2R) - sin(lat1R) * cos(lat2R) * cos(dLon)
        return (Math.toDegrees(atan2(y, x)) + 360) % 360
    }

    /**
     * Signed delta between two bearings, result in -180..180.
     */
    private fun bearingDelta(b1: Double, b2: Double): Double {
        var delta = b2 - b1
        while (delta > 180) delta -= 360
        while (delta < -180) delta += 360
        return delta
    }

    /**
     * Mutable cluster of user GPS positions, used only for route mirroring.
     */
    private data class UserCluster(
        var centerLat: Double,
        var centerLon: Double,
        val entries: MutableMap<Long, Pair<Double, Double>> // timestamp -> (lat, lon)
    )

    // -------------------------------------------------------------------------
    // Existing signals
    // -------------------------------------------------------------------------

    private fun filterStationary(
        sightings: List<DeviceSighting>,
        userHistory: List<Pair<Long, Pair<Double, Double>>>
    ): List<DeviceSighting> {
        if (userHistory.size < 2) return sightings

        return sightings.filter { sighting ->
            val windowStart = sighting.timestamp - 5 * 60 * 1000L
            val windowEnd = sighting.timestamp + 5 * 60 * 1000L
            val windowPositions = userHistory
                .filter { (ts, _) -> ts in windowStart..windowEnd }
                .map { (_, pos) -> pos }

            if (windowPositions.size < 2) {
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
            val userArrival = userHistory
                .filter { (_, pos) ->
                    haversineDistance(
                        pos.first, pos.second,
                        center.first, center.second
                    ) < LOCATION_CLUSTER_RADIUS_M
                }
                .minOfOrNull { (ts, _) -> ts }

            if (userArrival != null) {
                comparableCount++
                if (deviceArrival > userArrival) followerCount++
            }
        }

        if (comparableCount == 0) return 0
        return ((followerCount.toDouble() / comparableCount) * 20).toInt()
    }

    private fun buildClusters(sightings: List<DeviceSighting>): List<Pair<Pair<Double, Double>, List<DeviceSighting>>> {
        val clusters = mutableListOf<Pair<Pair<Double, Double>, MutableList<DeviceSighting>>>()
        for (s in sightings) {
            val existing = clusters.firstOrNull { (center, _) ->
                haversineDistance(
                    center.first, center.second,
                    s.latitude, s.longitude
                ) < LOCATION_CLUSTER_RADIUS_M
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