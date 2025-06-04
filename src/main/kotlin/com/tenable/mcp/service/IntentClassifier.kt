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
        "list" to listOf(
            "show", "list", "display", "get", "find", "search", "query",
            "what are", "what is", "tell me about", "give me"
        ),
        "export" to listOf(
            "export", "download", "save", "get csv", "get excel",
            "download as", "save as", "export as"
        ),
        "scan" to listOf(
            "scan", "run scan", "start scan", "initiate scan",
            "perform scan", "execute scan", "launch scan"
        )
    )

    private val scanStatusPatterns = mapOf(
        "completed" to listOf("completed", "finished", "done", "successful"),
        "running" to listOf("running", "in progress", "active", "ongoing"),
        "failed" to listOf("failed", "error", "unsuccessful", "stopped"),
        "scheduled" to listOf("scheduled", "planned", "queued", "pending")
    )

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
        val severity = determineSeverity(lowerPrompt, context)
        
        // Determine time range
        val timeRange = determineTimeRange(lowerPrompt, context)
        
        return Intent(
            action = action,
            severity = severity,
            timeRange = timeRange,
            cveId = determineCveId(prompt),
            assetId = determineAssetId(prompt),
            scanStatus = determineScanStatus(prompt)
        )
    }

    /**
     * Determine the action from the prompt
     * @param prompt The user's prompt
     * @param context Optional conversation context
     * @return The determined Action
     */
    private fun determineAction(prompt: String, context: ConversationContext?): Action {
        val lowerPrompt = prompt.lowercase()
        
        // Scan-related patterns
        val scanPatterns = mapOf(
            "list.*scan" to Action.LIST_SCANS,
            "show.*scan" to Action.LIST_SCANS,
            "get.*scan" to Action.LIST_SCANS,
            "display.*scan" to Action.LIST_SCANS,
            "view.*scan" to Action.LIST_SCANS,
            "scan.*list" to Action.LIST_SCANS,
            "scan.*history" to Action.LIST_SCANS,
            "scan.*schedule" to Action.LIST_SCANS,
            "scheduled.*scan" to Action.LIST_SCANS,
            "historical.*scan" to Action.LIST_SCANS,
            "past.*scan" to Action.LIST_SCANS,
            "previous.*scan" to Action.LIST_SCANS,
            "recent.*scan" to Action.LIST_SCANS,
            "last.*scan" to Action.LIST_SCANS,
            "all.*scan" to Action.LIST_SCANS,
            "scan.*status" to Action.LIST_SCANS,
            "scan.*result" to Action.LIST_SCANS,
            "scan.*report" to Action.LIST_SCANS
        )

        // Check for scan-related patterns first
        for ((pattern, action) in scanPatterns) {
            if (prompt.matches(Regex(pattern, RegexOption.IGNORE_CASE))) {
                return action
            }
        }

        // Asset-related patterns
        val assetPatterns = mapOf(
            "list.*asset" to Action.LIST_ASSETS,
            "show.*asset" to Action.LIST_ASSETS,
            "get.*asset" to Action.LIST_ASSETS,
            "display.*asset" to Action.LIST_ASSETS,
            "view.*asset" to Action.LIST_ASSETS,
            "asset.*list" to Action.LIST_ASSETS,
            "all.*asset" to Action.LIST_ASSETS
        )

        // Check for asset-related patterns
        for ((pattern, action) in assetPatterns) {
            if (prompt.matches(Regex(pattern, RegexOption.IGNORE_CASE))) {
                return action
            }
        }

        // Vulnerability-related patterns
        val vulnPatterns = mapOf(
            "list.*vulnerability" to Action.LIST_VULNERABILITIES,
            "show.*vulnerability" to Action.LIST_VULNERABILITIES,
            "get.*vulnerability" to Action.LIST_VULNERABILITIES,
            "display.*vulnerability" to Action.LIST_VULNERABILITIES,
            "view.*vulnerability" to Action.LIST_VULNERABILITIES,
            "vulnerability.*list" to Action.LIST_VULNERABILITIES,
            "all.*vulnerability" to Action.LIST_VULNERABILITIES,
            "vuln.*list" to Action.LIST_VULNERABILITIES,
            "show.*vuln" to Action.LIST_VULNERABILITIES,
            "list.*vuln" to Action.LIST_VULNERABILITIES
        )

        // Check for vulnerability-related patterns
        for ((pattern, action) in vulnPatterns) {
            if (prompt.matches(Regex(pattern, RegexOption.IGNORE_CASE))) {
                return action
            }
        }

        // Check context for previous action
        context?.currentContext?.get("lastAction")?.let { lastAction ->
            if (lastAction is String && lastAction.startsWith("list_")) {
                return try {
                    Action.valueOf(lastAction.uppercase())
                } catch (e: IllegalArgumentException) {
                    Action.LIST_VULNERABILITIES
                }
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
    private fun determineSeverity(prompt: String, context: ConversationContext? = null): Severity? {
        val lowerPrompt = prompt.lowercase()

        // Check for explicit severity mentions
        when {
            lowerPrompt.contains(Regex("(critical|severe|urgent)")) -> return Severity.CRITICAL
            lowerPrompt.contains(Regex("(high|important)")) -> return Severity.HIGH
            lowerPrompt.contains(Regex("(medium|moderate)")) -> return Severity.MEDIUM
            lowerPrompt.contains(Regex("(low|minor)")) -> return Severity.LOW
        }

        // If we have context and the prompt is about filtering, check previous severity
        context?.currentContext?.get("filters")?.let { filters ->
            if (filters is Map<*, *>) {
                val severity = filters["severity"] as? String
                if (severity != null) {
                    return try {
                        Severity.valueOf(severity.uppercase())
                    } catch (e: IllegalArgumentException) {
                        null
                    }
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
    private fun determineTimeRange(prompt: String, context: ConversationContext? = null): TimeRange? {
        val lowerPrompt = prompt.lowercase()

        // Check for explicit time mentions
        val now = LocalDateTime.now()
        when {
            lowerPrompt.contains(Regex("(last|past|previous)\\s+(\\d+)\\s+(day|week|month|year)")) -> {
                val matcher = Regex("(\\d+)\\s+(day|week|month|year)").find(lowerPrompt)
                if (matcher != null) {
                    val (amount, unit) = matcher.destructured
                    val duration = when (unit) {
                        "day" -> Duration.ofDays(amount.toLong())
                        "week" -> Duration.ofDays(amount.toLong() * 7)
                        "month" -> Duration.ofDays(amount.toLong() * 30)
                        "year" -> Duration.ofDays(amount.toLong() * 365)
                        else -> return null
                    }
                    return TimeRange(now.minus(duration), now)
                }
            }
            lowerPrompt.contains(Regex("(today|yesterday|this week|this month|this year)")) -> {
                return when {
                    lowerPrompt.contains("today") -> TimeRange(now.truncatedTo(ChronoUnit.DAYS), now)
                    lowerPrompt.contains("yesterday") -> {
                        val yesterday = now.minusDays(1)
                        TimeRange(yesterday.truncatedTo(ChronoUnit.DAYS), yesterday.plusDays(1).truncatedTo(ChronoUnit.DAYS))
                    }
                    lowerPrompt.contains("this week") -> {
                        val weekStart = now.with(TemporalAdjusters.previousOrSame(DayOfWeek.MONDAY))
                        TimeRange(weekStart.truncatedTo(ChronoUnit.DAYS), now)
                    }
                    lowerPrompt.contains("this month") -> {
                        val monthStart = now.with(TemporalAdjusters.firstDayOfMonth())
                        TimeRange(monthStart.truncatedTo(ChronoUnit.DAYS), now)
                    }
                    lowerPrompt.contains("this year") -> {
                        val yearStart = now.with(TemporalAdjusters.firstDayOfYear())
                        TimeRange(yearStart.truncatedTo(ChronoUnit.DAYS), now)
                    }
                    else -> null
                }
            }
        }

        // If we have context and the prompt is about filtering, check previous time range
        context?.currentContext?.get("filters")?.let { filters ->
            if (filters is Map<*, *>) {
                val timeRange = filters["timeRange"] as? String
                if (timeRange != null && timeRange != "all") {
                    val (start, end) = timeRange.split(" to ")
                    return TimeRange(
                        LocalDateTime.parse(start),
                        LocalDateTime.parse(end)
                    )
                }
            }
        }

        return null
    }

    private fun determineCveId(prompt: String): String? {
        return Regex("CVE-\\d{4}-\\d+").find(prompt)?.value
    }

    private fun determineAssetId(prompt: String): String? {
        return Regex("asset-\\d+").find(prompt)?.value
    }

    private fun determineScanStatus(prompt: String): String? {
        val lowerPrompt = prompt.lowercase()
        return scanStatusPatterns.entries.firstOrNull { (_, patterns) ->
            patterns.any { it in lowerPrompt }
        }?.key
    }
} 