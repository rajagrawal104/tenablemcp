package com.tenable.mcp.service

import com.tenable.mcp.client.TenableClient
import com.tenable.mcp.model.TimeRange
import org.springframework.stereotype.Service
import java.time.LocalDateTime
import java.time.format.DateTimeFormatter

@Service
class ExportService(private val tenableClient: TenableClient) {

    /**
     * Export vulnerabilities as CSV
     */
    fun exportVulnerabilitiesCsv(timeRange: TimeRange? = null): ByteArray {
        val vulns = tenableClient.listVulnerabilities(timeRange = timeRange)

        return buildString {
            // Write header
            appendLine("ID,Name,Severity,Description,Solution,CVSS Score,CVSS Vector,Affected Assets,Discovered At,Last Seen At")

            // Write data rows
            vulns.forEach { vuln ->
                appendLine(
                    "${vuln["id"]}," +
                    "\"${(vuln["name"] as? String)?.replace("\"", "\"\"") ?: ""}\"," +
                    "${vuln["severity"]}," +
                    "\"${(vuln["description"] as? String)?.replace("\"", "\"\"") ?: ""}\"," +
                    "\"${(vuln["solution"] as? String)?.replace("\"", "\"\"") ?: ""}\"," +
                    "${vuln["cvss_score"]}," +
                    "${vuln["cvss_vector"]}," +
                    "\"${(vuln["affected_assets"] as? List<String>)?.joinToString(";") ?: ""}\"," +
                    "${vuln["discovered_at"]}," +
                    "${vuln["last_seen_at"]}"
                )
            }
        }.toByteArray()
    }

    fun exportToCSV(timeRange: TimeRange? = null): String {
        val vulnerabilities = tenableClient.listVulnerabilities(timeRange = timeRange)
        val assets = tenableClient.listAssets(timeRange = timeRange)

        val csv = StringBuilder()
        
        // Add headers
        csv.append("Asset Name,IP Address,Severity,Category,Description,Discovered At,Status\n")
        
        // Add vulnerability data
        vulnerabilities.forEach { vuln ->
            val assetName = vuln["asset_name"] as? String ?: "Unknown"
            val ipAddress = vuln["ip_address"] as? String ?: "Unknown"
            val severity = vuln["severity"] as? String ?: "Unknown"
            val category = vuln["category"] as? String ?: "Unknown"
            val description = (vuln["description"] as? String ?: "Unknown").replace(",", ";")
            val discoveredAt = vuln["discovered_at"] as? String ?: "Unknown"
            val status = vuln["status"] as? String ?: "Unknown"
            
            csv.append("$assetName,$ipAddress,$severity,$category,$description,$discoveredAt,$status\n")
        }
        
        return csv.toString()
    }
} 