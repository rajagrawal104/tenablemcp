package com.tenable.mcp.service

import org.springframework.stereotype.Service
import java.time.LocalDateTime
import java.time.temporal.ChronoUnit
import java.time.temporal.TemporalAdjusters
import java.time.Duration
import java.time.DayOfWeek
import com.tenable.mcp.controller.ConversationContext

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
    fun classifyIntent(prompt: String, context: ConversationContext? = null): Intent {
        val action = determineAction(prompt, context)
        val severity = determineSeverity(prompt, context)
        val timeRange = determineTimeRange(prompt, context)
        val cveId = determineCveId(prompt)
        val assetId = determineAssetId(prompt)
        val scanStatus = determineScanStatus(prompt)

        return Intent(
            action = action,
            severity = severity,
            timeRange = timeRange,
            cveId = cveId,
            assetId = assetId,
            scanStatus = scanStatus
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
        
        // Check for scan-related actions first
        if (actionPatterns["scan"]?.any { it in lowerPrompt } == true) {
            return Action.LAUNCH_SCAN
        }

        // Check for export actions
        if (actionPatterns["export"]?.any { it in lowerPrompt } == true) {
            return if ("asset" in lowerPrompt) Action.EXPORT_ASSETS else Action.EXPORT_VULNERABILITIES
        }

        // Check for list actions
        if (actionPatterns["list"]?.any { it in lowerPrompt } == true) {
            return when {
                "scan" in lowerPrompt -> Action.LIST_SCANS
                "asset" in lowerPrompt -> Action.LIST_ASSETS
                else -> Action.LIST_VULNERABILITIES
            }
        }

        // Use context if available
        context?.let {
            return when (it.currentContext["lastAction"]) {
                "list_scans" -> Action.LIST_SCANS
                "list_assets" -> Action.LIST_ASSETS
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
        context?.let { ctx ->
            if (lowerPrompt.contains(Regex("(filter|show|only|just)")) &&
                ctx.currentContext["filters"] is Map<*, *>) {
                val filters = ctx.currentContext["filters"] as Map<*, *>
                filters["severity"]?.toString()?.let { severity ->
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
        context?.let { ctx ->
            if (lowerPrompt.contains(Regex("(filter|show|only|just)")) &&
                ctx.currentContext["filters"] is Map<*, *>) {
                val filters = ctx.currentContext["filters"] as Map<*, *>
                filters["timeRange"]?.toString()?.let { timeRangeStr ->
                    if (timeRangeStr != "all") {
                        val (start, end) = timeRangeStr.split(" to ")
                        return TimeRange(
                            LocalDateTime.parse(start),
                            LocalDateTime.parse(end)
                        )
                    }
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

    private fun extractScanId(prompt: String): String? {
        return Regex("scan-\\d+").find(prompt)?.value
    }

    private fun extractWebAppId(prompt: String): String? {
        return Regex("webapp-\\d+").find(prompt)?.value
    }

    private fun extractContainerId(prompt: String): String? {
        return Regex("container-\\d+").find(prompt)?.value
    }

    private fun extractCloudAccountId(prompt: String): String? {
        return Regex("cloud-\\d+").find(prompt)?.value
    }

    private fun extractReportId(prompt: String): String? {
        return Regex("report-\\d+").find(prompt)?.value
    }

    private fun extractPolicyId(prompt: String): String? {
        return Regex("policy-\\d+").find(prompt)?.value
    }

    private fun extractTagId(prompt: String): String? {
        return Regex("tag-\\d+").find(prompt)?.value
    }

    private fun extractUserId(prompt: String): String? {
        return Regex("user-\\d+").find(prompt)?.value
    }

    private fun extractGroupId(prompt: String): String? {
        return Regex("group-\\d+").find(prompt)?.value
    }

    private fun extractPermissionId(prompt: String): String? {
        return Regex("permission-\\d+").find(prompt)?.value
    }

    private fun determineScanStatus(prompt: String): String? {
        val lowerPrompt = prompt.lowercase()
        return scanStatusPatterns.entries.firstOrNull { (_, patterns) ->
            patterns.any { it in lowerPrompt }
        }?.key
    }
} 