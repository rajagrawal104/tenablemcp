package com.tenable.mcp.client

import com.tenable.mcp.model.*
import java.time.LocalDateTime

/**
 * Base interface for all Tenable API operations
 * This interface defines all available API endpoints grouped by functionality
 */
interface TenableApiClient {
    // Vulnerability Management APIs
    fun listVulnerabilities(filters: VulnerabilityFilters? = null): List<Vulnerability>
    fun getVulnerabilityDetails(vulnId: String): Vulnerability
    fun exportVulnerabilities(filters: VulnerabilityFilters? = null): ExportJob
    fun getVulnerabilityExportStatus(jobId: String): ExportStatus
    
    // Asset Management APIs
    fun listAssets(filters: AssetFilters? = null): List<Asset>
    fun getAssetDetails(assetId: String): Asset
    fun exportAssets(filters: AssetFilters? = null): ExportJob
    fun getAssetExportStatus(jobId: String): ExportStatus
    
    // Scan Management APIs
    fun listScans(filters: ScanFilters? = null): List<Scan>
    fun getScanDetails(scanId: String): Scan
    fun createScan(scanConfig: ScanConfig): Scan
    fun launchScan(scanId: String): ScanLaunch
    fun getScanStatus(scanId: String): ScanStatus
    
    // Web App Scanning APIs
    fun listWebApps(filters: WebAppFilters? = null): List<WebApp>
    fun getWebAppDetails(webAppId: String): WebApp
    fun createWebAppScan(webAppId: String, scanConfig: WebAppScanConfig): WebAppScan
    fun getWebAppScanStatus(scanId: String): WebAppScanStatus
    
    // Container Security APIs
    fun listContainers(filters: ContainerFilters? = null): List<Container>
    fun getContainerDetails(containerId: String): Container
    fun getContainerVulnerabilities(containerId: String): List<ContainerVulnerability>
    
    // Cloud Security APIs
    fun listCloudAccounts(filters: CloudAccountFilters? = null): List<CloudAccount>
    fun getCloudAccountDetails(accountId: String): CloudAccount
    fun getCloudVulnerabilities(accountId: String): List<CloudVulnerability>
    
    // Report Management APIs
    fun listReports(filters: ReportFilters? = null): List<Report>
    fun getReportDetails(reportId: String): Report
    fun createReport(reportConfig: ReportConfig): Report
    fun getReportStatus(reportId: String): ReportStatus
    fun downloadReport(reportId: String): ByteArray
    
    // Policy Management APIs
    fun listPolicies(filters: PolicyFilters? = null): List<Policy>
    fun getPolicyDetails(policyId: String): Policy
    fun createPolicy(policyConfig: PolicyConfig): Policy
    fun updatePolicy(policyId: String, policyConfig: PolicyConfig): Policy
    
    // Tag Management APIs
    fun listTags(filters: TagFilters? = null): List<Tag>
    fun createTag(tagConfig: TagConfig): Tag
    fun updateTag(tagId: String, tagConfig: TagConfig): Tag
    fun deleteTag(tagId: String)
    
    // User Management APIs
    fun listUsers(filters: UserFilters? = null): List<User>
    fun getUserDetails(userId: String): User
    fun createUser(userConfig: UserConfig): User
    fun updateUser(userId: String, userConfig: UserConfig): User
    
    // Group Management APIs
    fun listGroups(filters: GroupFilters? = null): List<Group>
    fun getGroupDetails(groupId: String): Group
    fun createGroup(groupConfig: GroupConfig): Group
    fun updateGroup(groupId: String, groupConfig: GroupConfig): Group
    
    // Access Control APIs
    fun listPermissions(filters: PermissionFilters? = null): List<Permission>
    fun getPermissionDetails(permissionId: String): Permission
    fun createPermission(permissionConfig: PermissionConfig): Permission
    fun updatePermission(permissionId: String, permissionConfig: PermissionConfig): Permission
    
    // Export Management APIs
    fun downloadExportChunk(jobId: String, chunkId: String): ByteArray
    fun cancelExport(jobId: String)
    fun listExportJobs(filters: ExportJobFilters? = null): List<ExportJob>
    
    // System Status APIs
    fun getSystemStatus(): SystemStatus
    fun getApiStatus(): ApiStatus
} 