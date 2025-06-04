package com.tenable.mcp.service

import org.springframework.stereotype.Service
import java.time.LocalDateTime
import java.time.temporal.ChronoUnit

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
    val permissionId: String? = null // Optional permission ID
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
    /**
     * Analyzes a user prompt and extracts the intent and relevant parameters
     * @param prompt The user's natural language prompt
     * @return Intent object containing the extracted information
     */
    fun classifyIntent(prompt: String): Intent {
        val lowerPrompt = prompt.lowercase()
        
        // Determine the main action based on keywords in the prompt
        val (action, subAction) = determineAction(lowerPrompt)
        
        // Extract severity level if mentioned in the prompt
        val severity = extractSeverity(lowerPrompt)
        
        // Extract time range if specified
        val timeRange = extractTimeRange(lowerPrompt)
        
        // Extract various IDs from the prompt
        val cveId = extractCveId(lowerPrompt)
        val assetId = extractAssetId(lowerPrompt)
        val scanId = extractScanId(lowerPrompt)
        val webAppId = extractWebAppId(lowerPrompt)
        val containerId = extractContainerId(lowerPrompt)
        val cloudAccountId = extractCloudAccountId(lowerPrompt)
        val reportId = extractReportId(lowerPrompt)
        val policyId = extractPolicyId(lowerPrompt)
        val tagId = extractTagId(lowerPrompt)
        val userId = extractUserId(lowerPrompt)
        val groupId = extractGroupId(lowerPrompt)
        val permissionId = extractPermissionId(lowerPrompt)

        return Intent(
            action = action,
            subAction = subAction,
            severity = severity,
            timeRange = timeRange,
            cveId = cveId,
            assetId = assetId,
            scanId = scanId,
            webAppId = webAppId,
            containerId = containerId,
            cloudAccountId = cloudAccountId,
            reportId = reportId,
            policyId = policyId,
            tagId = tagId,
            userId = userId,
            groupId = groupId,
            permissionId = permissionId
        )
    }

    private fun determineAction(prompt: String): Pair<Action, SubAction?> {
        // First determine the main action
        val action = when {
            // Vulnerability Management
            prompt.contains(Regex("(vulnerabilit|vuln|issue|finding)")) -> {
                when {
                    prompt.contains(Regex("(export|download)")) -> Action.EXPORT_VULNERABILITIES
                    prompt.contains(Regex("(detail|info|about)")) -> Action.GET_VULNERABILITY
                    else -> Action.LIST_VULNERABILITIES
                }
            }
            // Asset Management
            prompt.contains(Regex("(asset|host|device)")) -> {
                when {
                    prompt.contains(Regex("(export|download)")) -> Action.EXPORT_ASSETS
                    prompt.contains(Regex("(detail|info|about)")) -> Action.GET_ASSET
                    else -> Action.LIST_ASSETS
                }
            }
            // Scan Management
            prompt.contains(Regex("(scan|scanner)")) -> {
                when {
                    prompt.contains(Regex("(create|new|start)")) -> Action.CREATE_SCAN
                    prompt.contains(Regex("(launch|run|execute)")) -> Action.LAUNCH_SCAN
                    prompt.contains(Regex("(status|progress)")) -> Action.GET_SCAN_STATUS
                    prompt.contains(Regex("(detail|info|about)")) -> Action.GET_SCAN
                    else -> Action.LIST_SCANS
                }
            }
            // Web App Scanning
            prompt.contains(Regex("(web app|webapp|website)")) -> {
                when {
                    prompt.contains(Regex("(create|new|start)")) -> Action.CREATE_WEB_APP_SCAN
                    prompt.contains(Regex("(status|progress)")) -> Action.GET_WEB_APP_SCAN_STATUS
                    prompt.contains(Regex("(detail|info|about)")) -> Action.GET_WEB_APP
                    else -> Action.LIST_WEB_APPS
                }
            }
            // Container Security
            prompt.contains(Regex("(container|docker)")) -> {
                when {
                    prompt.contains(Regex("(vulnerabilit|vuln|issue)")) -> Action.GET_CONTAINER_VULNERABILITIES
                    prompt.contains(Regex("(detail|info|about)")) -> Action.GET_CONTAINER
                    else -> Action.LIST_CONTAINERS
                }
            }
            // Cloud Security
            prompt.contains(Regex("(cloud|aws|azure|gcp)")) -> {
                when {
                    prompt.contains(Regex("(vulnerabilit|vuln|issue)")) -> Action.GET_CLOUD_VULNERABILITIES
                    prompt.contains(Regex("(detail|info|about)")) -> Action.GET_CLOUD_ACCOUNT
                    else -> Action.LIST_CLOUD_ACCOUNTS
                }
            }
            // Report Management
            prompt.contains(Regex("(report|export)")) -> {
                when {
                    prompt.contains(Regex("(create|new|generate)")) -> Action.CREATE_REPORT
                    prompt.contains(Regex("(download|get)")) -> Action.DOWNLOAD_REPORT
                    prompt.contains(Regex("(status|progress)")) -> Action.GET_REPORT_STATUS
                    prompt.contains(Regex("(detail|info|about)")) -> Action.GET_REPORT
                    else -> Action.LIST_REPORTS
                }
            }
            // Policy Management
            prompt.contains(Regex("(policy|policies)")) -> {
                when {
                    prompt.contains(Regex("(create|new)")) -> Action.CREATE_POLICY
                    prompt.contains(Regex("(update|modify|change)")) -> Action.UPDATE_POLICY
                    prompt.contains(Regex("(detail|info|about)")) -> Action.GET_POLICY
                    else -> Action.LIST_POLICIES
                }
            }
            // Tag Management
            prompt.contains(Regex("(tag|tags)")) -> {
                when {
                    prompt.contains(Regex("(create|new|add)")) -> Action.CREATE_TAG
                    prompt.contains(Regex("(update|modify|change)")) -> Action.UPDATE_TAG
                    prompt.contains(Regex("(delete|remove)")) -> Action.DELETE_TAG
                    else -> Action.LIST_TAGS
                }
            }
            // User Management
            prompt.contains(Regex("(user|users)")) -> {
                when {
                    prompt.contains(Regex("(create|new|add)")) -> Action.CREATE_USER
                    prompt.contains(Regex("(update|modify|change)")) -> Action.UPDATE_USER
                    prompt.contains(Regex("(detail|info|about)")) -> Action.GET_USER
                    else -> Action.LIST_USERS
                }
            }
            // Group Management
            prompt.contains(Regex("(group|groups)")) -> {
                when {
                    prompt.contains(Regex("(create|new|add)")) -> Action.CREATE_GROUP
                    prompt.contains(Regex("(update|modify|change)")) -> Action.UPDATE_GROUP
                    prompt.contains(Regex("(detail|info|about)")) -> Action.GET_GROUP
                    else -> Action.LIST_GROUPS
                }
            }
            // Access Control
            prompt.contains(Regex("(permission|permissions)")) -> {
                when {
                    prompt.contains(Regex("(create|new|add)")) -> Action.CREATE_PERMISSION
                    prompt.contains(Regex("(update|modify|change)")) -> Action.UPDATE_PERMISSION
                    prompt.contains(Regex("(detail|info|about)")) -> Action.GET_PERMISSION
                    else -> Action.LIST_PERMISSIONS
                }
            }
            // System Status
            prompt.contains(Regex("(status|health|system)")) -> {
                when {
                    prompt.contains(Regex("(api|endpoint)")) -> Action.GET_API_STATUS
                    else -> Action.GET_SYSTEM_STATUS
                }
            }
            else -> Action.UNKNOWN
        }

        // Then determine the sub-action if applicable
        val subAction = when {
            prompt.contains(Regex("(create|new|add)")) -> SubAction.CREATE
            prompt.contains(Regex("(update|modify|change)")) -> SubAction.UPDATE
            prompt.contains(Regex("(delete|remove)")) -> SubAction.DELETE
            prompt.contains(Regex("(export|download)")) -> SubAction.EXPORT
            prompt.contains(Regex("(launch|run|execute)")) -> SubAction.LAUNCH
            prompt.contains(Regex("(status|progress)")) -> SubAction.STATUS
            else -> null
        }

        return Pair(action, subAction)
    }

    private fun extractSeverity(prompt: String): Severity? {
        return when {
            prompt.contains(Regex("(critical|crit)")) -> Severity.CRITICAL
            prompt.contains(Regex("(high|severe)")) -> Severity.HIGH
            prompt.contains(Regex("(medium|moderate)")) -> Severity.MEDIUM
            prompt.contains(Regex("(low|minor)")) -> Severity.LOW
            else -> null
        }
    }

    private fun extractTimeRange(prompt: String): TimeRange? {
        val now = LocalDateTime.now()
        
        return when {
            // Match patterns like "last 7 days" or "past 3 days"
            prompt.contains(Regex("(last|past) (\\d+) (day|days)")) -> {
                val days = Regex("(\\d+)").find(prompt)?.value?.toIntOrNull() ?: 7
                TimeRange(now.minus(days.toLong(), ChronoUnit.DAYS), now)
            }
            // Match patterns like "last 2 weeks" or "past 1 week"
            prompt.contains(Regex("(last|past) (\\d+) (week|weeks)")) -> {
                val weeks = Regex("(\\d+)").find(prompt)?.value?.toIntOrNull() ?: 1
                TimeRange(now.minus(weeks.toLong() * 7, ChronoUnit.DAYS), now)
            }
            // Match patterns like "last 3 months" or "past 1 month"
            prompt.contains(Regex("(last|past) (\\d+) (month|months)")) -> {
                val months = Regex("(\\d+)").find(prompt)?.value?.toIntOrNull() ?: 1
                TimeRange(now.minus(months.toLong(), ChronoUnit.MONTHS), now)
            }
            else -> null
        }
    }

    private fun extractCveId(prompt: String): String? {
        return Regex("CVE-\\d{4}-\\d+").find(prompt)?.value
    }

    private fun extractAssetId(prompt: String): String? {
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
} 