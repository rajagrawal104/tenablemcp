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
        
        // Check for export-related patterns first
        if (lowerPrompt.contains(Regex("(export|download|save|get csv|get excel|download as|save as|export as|csv)"))) {
            return if (lowerPrompt.contains(Regex("(asset|host|server|machine)"))) {
                Action.EXPORT_ASSETS
            } else if (lowerPrompt.contains(Regex("(scan|scanning)"))) {
                Action.EXPORT_SCANS
            } else {
                Action.EXPORT_VULNERABILITIES
            }
        }

        // Check for scan-related patterns
        if (lowerPrompt.contains(Regex("(scan|run scan|start scan|initiate scan|perform scan|execute scan|launch scan)"))) {
            return Action.START_SCAN
        }
        
        // Asset-related patterns
        if (lowerPrompt.contains(Regex("(asset|host|server|machine)"))) {
            return Action.LIST_ASSETS
        }

        // Scan-related patterns - expanded to catch more variations
        if (lowerPrompt.contains(Regex("(scan|scan list|scan history|scan schedule|scheduled scan|historical scan|past scan|previous scan|recent scan|last scan|all scan|scan status|scan result|scan report|show.*scan|list.*scan|get.*scan|display.*scan|view.*scan)"))) {
            return Action.LIST_SCANS
        }

        // Check context for previous action
        context?.currentContext?.get("lastAction")?.let { lastAction ->
            if (lastAction is String) {
                return try {
                    Action.valueOf(lastAction.uppercase())
                } catch (e: IllegalArgumentException) {
                    Action.LIST_VULNERABILITIES
                }
            }
        }

        // If no specific pattern is matched, check for vulnerability-related keywords
        if (lowerPrompt.contains(Regex("(vulnerability|vuln|security issue|security risk|security problem)"))) {
            return Action.LIST_VULNERABILITIES
        }

        // If still no match, check if the prompt is a follow-up question
        if (context?.history?.isNotEmpty() == true) {
            val lastMessage = context.history.last()
            if (lastMessage.role == "assistant") {
                // If the last message was about vulnerabilities, continue with vulnerabilities
                if (lastMessage.content.contains(Regex("(vulnerability|vuln)"))) {
                    return Action.LIST_VULNERABILITIES
                }
                // If the last message was about assets, continue with assets
                if (lastMessage.content.contains(Regex("(asset|host|server)"))) {
                    return Action.LIST_ASSETS
                }
                // If the last message was about scans, continue with scans
                if (lastMessage.content.contains(Regex("(scan|scanning)"))) {
                    return Action.LIST_SCANS
                }
            }
        }

        // Default to listing vulnerabilities only if no other context is available
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