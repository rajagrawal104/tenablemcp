package com.tenable.mcp.service

import org.springframework.stereotype.Service
import java.time.LocalDateTime
import java.time.temporal.ChronoUnit
import java.time.temporal.TemporalAdjusters
import java.time.Duration
import java.time.DayOfWeek
import com.tenable.mcp.model.ConversationContext
import com.tenable.mcp.model.Intent
import com.tenable.mcp.model.Action
import com.tenable.mcp.model.Severity
import com.tenable.mcp.model.TimeRange
import com.tenable.mcp.model.SubAction
import java.time.format.DateTimeFormatter

// Data class representing the extracted intent from a user prompt
data class Intent(
    val action: Action,          // The main action to perform
    val subAction: SubAction? = null,  // Optional sub-action for more specific operations
    val severity: Severity? = null,  // Optional severity filter
    val timeRange: TimeRange? = null, // Optional time range filter
    val cveId: String? = null,      // Optional CVE ID filter
    val assetId: String? = null,    // Optional asset ID filter
    val scanId: String? = null,     // Optional scan ID
    val webAppId: String? = null,   // Optional web app ID
    val containerId: String? = null, // Optional container ID
    val cloudAccountId: String? = null, // Optional cloud account ID
    val reportId: String? = null,   // Optional report ID
    val policyId: String? = null,   // Optional policy ID
    val tagId: String? = null,      // Optional tag ID
    val userId: String? = null,     // Optional user ID
    val groupId: String? = null,    // Optional group ID
    val permissionId: String? = null, // Optional permission ID
    val scanStatus: String? = null   // Optional scan status
)

// Enum defining possible actions that can be performed
enum class SubAction {
    CREATE,     // Create a new resource
    UPDATE,     // Update an existing resource
    DELETE,     // Delete a resource
    EXPORT,     // Export data
    DOWNLOAD,   // Download data
    LAUNCH,     // Launch a scan
    STATUS      // Get status
}

@Service
class IntentClassifier {
    private val actionPatterns = mapOf(
        "list" to listOf("show", "list", "display", "get", "find", "search", "all"),
        "export" to listOf("export", "download", "save", "get csv", "get report"),
        "start" to listOf("start", "run", "launch", "initiate", "begin")
    )

    private val severityPatterns = mapOf(
        "critical" to listOf("critical", "severe", "high risk"),
        "high" to listOf("high", "serious"),
        "medium" to listOf("medium", "moderate"),
        "low" to listOf("low", "minor"),
        "info" to listOf("info", "information", "informational")
    )

    private val timeRangePatterns = mapOf(
        "last_24h" to listOf("last 24 hours", "past day", "last day", "24 hours"),
        "last_7d" to listOf("last 7 days", "past week", "last week", "7 days"),
        "last_30d" to listOf("last 30 days", "past month", "last month", "30 days"),
        "last_90d" to listOf("last 90 days", "past quarter", "last quarter", "90 days")
    )

    private val scanPatterns = listOf("scan", "scans", "scanning")

    /**
     * Analyze a user prompt to determine their intent
     * @param prompt The user's natural language prompt
     * @param context Optional conversation context
     * @return Intent object containing the extracted action and parameters
     */
    fun classifyIntent(prompt: String, context: ConversationContext? = null): Intent {
        val lowerPrompt = prompt.lowercase()
        
        // Determine the action
        val action = determineAction(lowerPrompt, context)
        
        // Determine severity if applicable
        val severity = if (action in listOf(Action.LIST_VULNERABILITIES, Action.EXPORT_VULNERABILITIES)) {
            determineSeverity(lowerPrompt, context)
        } else null
        
        // Determine time range
        val timeRange = determineTimeRange(lowerPrompt, context)
        
        // Extract CVE ID if present
        val cveId = extractCveId(lowerPrompt)
        
        // Extract asset ID if present
        val assetId = extractAssetId(lowerPrompt)
        
        // Extract scan ID if present
        val scanId = extractScanId(lowerPrompt)

        return Intent(
            action = action,
            severity = severity,
            timeRange = timeRange,
            cveId = cveId,
            assetId = assetId,
            scanId = scanId
        )
    }

    /**
     * Determine the action from the prompt
     * @param prompt The user's prompt
     * @param context Optional conversation context
     * @return The determined Action
     */
    private fun determineAction(prompt: String, context: ConversationContext?): Action {
        // Check for scan-related keywords
        if (scanPatterns.any { prompt.contains(it) }) {
            return when {
                actionPatterns["start"]?.any { prompt.contains(it) } == true -> Action.START_SCAN
                actionPatterns["export"]?.any { prompt.contains(it) } == true -> Action.EXPORT_SCANS
                else -> Action.LIST_SCANS
            }
        }

        // Check for export intent
        if (actionPatterns["export"]?.any { prompt.contains(it) } == true) {
            return if (prompt.contains("asset") || prompt.contains("host")) {
                Action.EXPORT_ASSETS
            } else {
                Action.EXPORT_VULNERABILITIES
            }
        }

        // Check for list intent - including "show all" cases
        if (actionPatterns["list"]?.any { prompt.contains(it) } == true || prompt.contains("all")) {
            return if (prompt.contains("asset") || prompt.contains("host")) {
                Action.LIST_ASSETS
            } else {
                Action.LIST_VULNERABILITIES
            }
        }

        // Use context if available
        context?.let {
            return when {
                it.currentContext["lastAction"] == "scan" -> Action.LIST_SCANS
                it.currentContext["lastAction"] == "asset" -> Action.LIST_ASSETS
                else -> Action.LIST_VULNERABILITIES
            }
        }

        // Default to listing vulnerabilities
        return Action.LIST_VULNERABILITIES
    }

    /**
     * Determine the severity from the prompt
     * @param prompt The user's prompt
     * @param context Optional conversation context
     * @return The determined Severity, or null if not specified
     */
    private fun determineSeverity(prompt: String, context: ConversationContext?): Severity? {
        // Check query for severity keywords
        severityPatterns.forEach { (severity, patterns) ->
            if (patterns.any { prompt.contains(it) }) {
                return Severity.valueOf(severity.uppercase())
            }
        }

        // Use context if available
        context?.let {
            val lastSeverity = it.currentContext["lastSeverity"]
            if (lastSeverity is String) {
                return try {
                    Severity.valueOf(lastSeverity.uppercase())
                } catch (e: Exception) {
                    null
                }
            }
        }
        return null
    }

    /**
     * Determine the time range from the prompt
     * @param prompt The user's prompt
     * @param context Optional conversation context
     * @return The determined TimeRange, or null if not specified
     */
    private fun determineTimeRange(prompt: String, context: ConversationContext?): TimeRange? {
        // Check query for time range keywords
        timeRangePatterns.forEach { (range, patterns) ->
            if (patterns.any { prompt.contains(it) }) {
                val end = LocalDateTime.now()
                val start = when (range) {
                    "last_24h" -> end.minusHours(24)
                    "last_7d" -> end.minusDays(7)
                    "last_30d" -> end.minusDays(30)
                    "last_90d" -> end.minusDays(90)
                    else -> end.minusDays(30) // Default to last 30 days
                }
                return TimeRange(start, end)
            }
        }

        // Use context if available
        context?.let {
            val lastTimeRange = it.currentContext["lastTimeRange"]
            if (lastTimeRange is String && lastTimeRange.contains(" to ")) {
                val formatter = DateTimeFormatter.ISO_DATE_TIME
                val parts = lastTimeRange.split(" to ")
                if (parts.size == 2) {
                    val start = LocalDateTime.parse(parts[0], formatter)
                    val end = LocalDateTime.parse(parts[1], formatter)
                    return TimeRange(start, end)
                }
            }
        }
        return null
    }

    private fun extractCveId(prompt: String): String? {
        val cvePattern = "CVE-\\d{4}-\\d{4,7}".toRegex()
        return cvePattern.find(prompt)?.value
    }

    private fun extractAssetId(prompt: String): String? {
        val assetPattern = "asset[_-]?id[=:]?\\s*([a-zA-Z0-9-]+)".toRegex()
        return assetPattern.find(prompt)?.groupValues?.get(1)
    }

    private fun extractScanId(prompt: String): String? {
        val scanPattern = "scan[_-]?id[=:]?\\s*([a-zA-Z0-9-]+)".toRegex()
        return scanPattern.find(prompt)?.groupValues?.get(1)
    }
} 