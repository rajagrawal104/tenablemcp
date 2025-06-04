package com.tenable.mcp.service

import org.springframework.stereotype.Service
import java.time.LocalDateTime
import java.time.temporal.ChronoUnit
import java.time.temporal.TemporalAdjusters
import java.time.Duration
import java.time.DayOfWeek
import com.tenable.mcp.controller.ConversationContext
import com.tenable.mcp.model.ConversationContext as ModelConversationContext
import com.tenable.mcp.model.Intent

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
enum class Action {
    // Vulnerability Management
    LIST_VULNERABILITIES,  // List vulnerabilities matching criteria
    GET_VULNERABILITY,     // Get details of a specific vulnerability
    EXPORT_VULNERABILITIES, // Export vulnerabilities to a report
    
    // Asset Management
    LIST_ASSETS,          // List assets matching criteria
    GET_ASSET,            // Get details of a specific asset
    EXPORT_ASSETS,        // Export assets to a report
    
    // Scan Management
    LIST_SCANS,           // List scans matching criteria
    GET_SCAN,             // Get details of a specific scan
    CREATE_SCAN,          // Create a new scan
    LAUNCH_SCAN,          // Launch a scan
    GET_SCAN_STATUS,      // Get status of a scan
    
    // Web App Scanning
    LIST_WEB_APPS,        // List web apps matching criteria
    GET_WEB_APP,          // Get details of a specific web app
    CREATE_WEB_APP_SCAN,  // Create a new web app scan
    GET_WEB_APP_SCAN_STATUS, // Get status of a web app scan
    
    // Container Security
    LIST_CONTAINERS,      // List containers matching criteria
    GET_CONTAINER,        // Get details of a specific container
    GET_CONTAINER_VULNERABILITIES, // Get vulnerabilities in a container
    
    // Cloud Security
    LIST_CLOUD_ACCOUNTS,  // List cloud accounts matching criteria
    GET_CLOUD_ACCOUNT,    // Get details of a specific cloud account
    GET_CLOUD_VULNERABILITIES, // Get vulnerabilities in a cloud account
    
    // Report Management
    LIST_REPORTS,         // List reports matching criteria
    GET_REPORT,           // Get details of a specific report
    CREATE_REPORT,        // Create a new report
    GET_REPORT_STATUS,    // Get status of a report
    DOWNLOAD_REPORT,      // Download a report
    
    // Policy Management
    LIST_POLICIES,        // List policies matching criteria
    GET_POLICY,           // Get details of a specific policy
    CREATE_POLICY,        // Create a new policy
    UPDATE_POLICY,        // Update an existing policy
    
    // Tag Management
    LIST_TAGS,            // List tags matching criteria
    CREATE_TAG,           // Create a new tag
    UPDATE_TAG,           // Update an existing tag
    DELETE_TAG,           // Delete a tag
    
    // User Management
    LIST_USERS,           // List users matching criteria
    GET_USER,             // Get details of a specific user
    CREATE_USER,          // Create a new user
    UPDATE_USER,          // Update an existing user
    
    // Group Management
    LIST_GROUPS,          // List groups matching criteria
    GET_GROUP,            // Get details of a specific group
    CREATE_GROUP,         // Create a new group
    UPDATE_GROUP,         // Update an existing group
    
    // Access Control
    LIST_PERMISSIONS,     // List permissions matching criteria
    GET_PERMISSION,       // Get details of a specific permission
    CREATE_PERMISSION,    // Create a new permission
    UPDATE_PERMISSION,    // Update an existing permission
    
    // System Status
    GET_SYSTEM_STATUS,    // Get system status
    GET_API_STATUS,       // Get API status
    
    UNKNOWN              // Unable to determine the action
}

// Enum defining possible sub-actions for more specific operations
enum class SubAction {
    CREATE,     // Create a new resource
    UPDATE,     // Update an existing resource
    DELETE,     // Delete a resource
    EXPORT,     // Export data
    DOWNLOAD,   // Download data
    LAUNCH,     // Launch a scan
    STATUS      // Get status
}

// Enum defining severity levels for vulnerabilities
enum class Severity {
    CRITICAL,  // Critical severity issues
    HIGH,      // High severity issues
    MEDIUM,    // Medium severity issues
    LOW        // Low severity issues
}

// Data class representing a time range with start and end times
data class TimeRange(
    val start: LocalDateTime,  // Start of the time range
    val end: LocalDateTime     // End of the time range
)

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
    fun classifyIntent(prompt: String, context: ModelConversationContext? = null): Intent {
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
    private fun determineAction(prompt: String, context: ModelConversationContext?): Action {
        val lowerPrompt = prompt.lowercase()
        
        // Scan-related patterns
        val scanPatterns = mapOf(
            "list.*scan" to "list_scans",
            "show.*scan" to "list_scans",
            "get.*scan" to "list_scans",
            "display.*scan" to "list_scans",
            "view.*scan" to "list_scans",
            "scan.*list" to "list_scans",
            "scan.*history" to "list_scans",
            "scan.*schedule" to "list_scans",
            "scheduled.*scan" to "list_scans",
            "historical.*scan" to "list_scans",
            "past.*scan" to "list_scans",
            "previous.*scan" to "list_scans",
            "recent.*scan" to "list_scans",
            "last.*scan" to "list_scans",
            "all.*scan" to "list_scans",
            "scan.*status" to "list_scans",
            "scan.*result" to "list_scans",
            "scan.*report" to "list_scans"
        )

        // Check for scan-related patterns first
        for ((pattern, action) in scanPatterns) {
            if (prompt.matches(Regex(pattern, RegexOption.IGNORE_CASE))) {
                return Action.valueOf(action)
            }
        }

        // Asset-related patterns
        val assetPatterns = mapOf(
            "list.*asset" to "list_assets",
            "show.*asset" to "list_assets",
            "get.*asset" to "list_assets",
            "display.*asset" to "list_assets",
            "view.*asset" to "list_assets",
            "asset.*list" to "list_assets",
            "all.*asset" to "list_assets"
        )

        // Check for asset-related patterns
        for ((pattern, action) in assetPatterns) {
            if (prompt.matches(Regex(pattern, RegexOption.IGNORE_CASE))) {
                return Action.valueOf(action)
            }
        }

        // Vulnerability-related patterns
        val vulnPatterns = mapOf(
            "list.*vulnerability" to "list_vulnerabilities",
            "show.*vulnerability" to "list_vulnerabilities",
            "get.*vulnerability" to "list_vulnerabilities",
            "display.*vulnerability" to "list_vulnerabilities",
            "view.*vulnerability" to "list_vulnerabilities",
            "vulnerability.*list" to "list_vulnerabilities",
            "all.*vulnerability" to "list_vulnerabilities",
            "vuln.*list" to "list_vulnerabilities",
            "show.*vuln" to "list_vulnerabilities",
            "list.*vuln" to "list_vulnerabilities"
        )

        // Check for vulnerability-related patterns
        for ((pattern, action) in vulnPatterns) {
            if (prompt.matches(Regex(pattern, RegexOption.IGNORE_CASE))) {
                return Action.valueOf(action)
            }
        }

        // Check context for previous action
        context?.currentContext?.get("lastAction")?.let { lastAction ->
            if (lastAction is String && lastAction.startsWith("list_")) {
                return Action.valueOf(lastAction)
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
    private fun determineSeverity(prompt: String, context: ModelConversationContext? = null): Severity? {
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
    private fun determineTimeRange(prompt: String, context: ModelConversationContext? = null): TimeRange? {
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