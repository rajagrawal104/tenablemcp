package com.tenable.mcp.model

import java.time.LocalDateTime

// Severity levels for vulnerabilities and findings
enum class Severity {
    CRITICAL, HIGH, MEDIUM, LOW, INFO, UNKNOWN
}

// Status for web application scans
enum class WebAppScanStatus {
    PENDING, RUNNING, COMPLETED, FAILED, CANCELLED
}

// Common Models
data class ExportJob(
    val id: String,
    val status: String,
    val type: String,
    val createdAt: LocalDateTime,
    val updatedAt: LocalDateTime
)

data class ExportStatus(
    val status: String,
    val progress: Int,
    val chunks: List<String>,
    val totalSize: Long
)

// Vulnerability Management Models
data class Vulnerability(
    val id: String,
    val name: String,
    val severity: Severity,
    val description: String,
    val solution: String,
    val cvssScore: Double,
    val cvssVector: String,
    val affectedAssets: List<String>,
    val discoveredAt: LocalDateTime,
    val lastSeenAt: LocalDateTime
)

data class VulnerabilityFilters(
    val severity: Severity? = null,
    val timeRange: TimeRange? = null,
    val cveId: String? = null,
    val assetId: String? = null,
    val pluginId: String? = null
)

// Asset Management Models
data class Asset(
    val id: String,
    val name: String,
    val ipAddress: String,
    val hostname: String,
    val operatingSystem: String,
    val tags: List<Tag>,
    val lastSeen: LocalDateTime,
    val vulnerabilities: List<Vulnerability>
)

data class AssetFilters(
    val timeRange: TimeRange? = null,
    val tagId: String? = null,
    val operatingSystem: String? = null,
    val ipAddress: String? = null
)

// Scan Management Models
data class Scan(
    val id: String,
    val name: String,
    val status: String,
    val targets: List<String>,
    val policy: Policy,
    val schedule: Schedule? = null,
    val lastRun: LocalDateTime? = null,
    val nextRun: LocalDateTime? = null
)

data class ScanConfig(
    val name: String,
    val targets: List<String>,
    val policyId: String,
    val schedule: Schedule? = null
)

data class ScanLaunch(
    val scanId: String,
    val scanUuid: String,
    val status: String
)

data class ScanStatus(
    val status: String,
    val progress: Int,
    val startTime: LocalDateTime,
    val endTime: LocalDateTime?
)

data class ScanFilters(
    val status: String? = null,
    val timeRange: TimeRange? = null,
    val policyId: String? = null
)

// Web App Scanning Models
data class WebApp(
    val id: String,
    val name: String,
    val url: String,
    val status: String,
    val lastScan: LocalDateTime? = null
)

data class WebAppScan(
    val id: String,
    val webAppId: String,
    val status: String,
    val startTime: LocalDateTime,
    val endTime: LocalDateTime?
)

data class WebAppScanConfig(
    val scanType: String,
    val options: Map<String, Any>
)

data class WebAppFilters(
    val status: String? = null,
    val timeRange: TimeRange? = null
)

// Container Security Models
data class Container(
    val id: String,
    val name: String,
    val image: String,
    val status: String,
    val vulnerabilities: List<ContainerVulnerability>
)

data class ContainerVulnerability(
    val id: String,
    val name: String,
    val severity: Severity,
    val layer: String,
    val packageName: String
)

data class ContainerFilters(
    val status: String? = null,
    val image: String? = null
)

// Cloud Security Models
data class CloudAccount(
    val id: String,
    val name: String,
    val provider: String,
    val region: String,
    val status: String
)

data class CloudVulnerability(
    val id: String,
    val name: String,
    val severity: Severity,
    val resource: String,
    val region: String
)

data class CloudAccountFilters(
    val provider: String? = null,
    val region: String? = null,
    val status: String? = null
)

// Report Management Models
data class Report(
    val id: String,
    val name: String,
    val type: String,
    val status: String,
    val createdAt: LocalDateTime,
    val downloadUrl: String?
)

data class ReportConfig(
    val name: String,
    val type: String,
    val format: String,
    val filters: Map<String, Any>
)

data class ReportStatus(
    val status: String,
    val progress: Int,
    val downloadUrl: String?
)

data class ReportFilters(
    val type: String? = null,
    val timeRange: TimeRange? = null
)

// Policy Management Models
data class Policy(
    val id: String,
    val name: String,
    val description: String,
    val settings: Map<String, Any>,
    val createdBy: String,
    val createdAt: LocalDateTime
)

data class PolicyConfig(
    val name: String,
    val description: String,
    val settings: Map<String, Any>
)

data class PolicyFilters(
    val createdBy: String? = null,
    val timeRange: TimeRange? = null
)

// Tag Management Models
data class Tag(
    val id: String,
    val name: String,
    val category: String,
    val value: String
)

data class TagConfig(
    val name: String,
    val category: String,
    val value: String
)

data class TagFilters(
    val category: String? = null
)

// User Management Models
data class User(
    val id: String,
    val username: String,
    val email: String,
    val permissions: List<Permission>,
    val groups: List<Group>,
    val lastLogin: LocalDateTime?
)

data class UserConfig(
    val username: String,
    val email: String,
    val permissions: List<String>,
    val groups: List<String>
)

data class UserFilters(
    val groupId: String? = null,
    val permissionId: String? = null
)

// Group Management Models
data class Group(
    val id: String,
    val name: String,
    val description: String,
    val permissions: List<Permission>,
    val users: List<User>
)

data class GroupConfig(
    val name: String,
    val description: String,
    val permissions: List<String>
)

data class GroupFilters(
    val permissionId: String? = null
)

// Access Control Models
data class Permission(
    val id: String,
    val name: String,
    val description: String,
    val type: String
)

data class PermissionConfig(
    val name: String,
    val description: String,
    val type: String
)

data class PermissionFilters(
    val type: String? = null
)

// Export Management Models
data class ExportJobFilters(
    val type: String? = null,
    val status: String? = null,
    val timeRange: TimeRange? = null
)

// System Status Models
data class SystemStatus(
    val status: String,
    val version: String,
    val build: String,
    val timestamp: LocalDateTime
)

data class ApiStatus(
    val status: String,
    val version: String,
    val timestamp: LocalDateTime
)

// Common Models
data class TimeRange(
    val start: LocalDateTime,
    val end: LocalDateTime
)

data class Schedule(
    val type: String,
    val interval: Int,
    val startTime: LocalDateTime,
    val timezone: String
)

data class ConversationContext(
    val history: List<Message> = emptyList(),
    val currentContext: Map<String, Any> = emptyMap()
)

data class Message(
    val role: String,
    val content: String
)

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

enum class SubAction {
    CREATE,     // Create a new resource
    UPDATE,     // Update an existing resource
    DELETE,     // Delete a resource
    EXPORT,     // Export data
    DOWNLOAD,   // Download data
    LAUNCH,     // Launch a scan
    STATUS      // Get status
} 