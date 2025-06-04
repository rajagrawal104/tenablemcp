package com.tenable.mcp.controller

import com.tenable.mcp.service.TimeRange
import com.tenable.mcp.service.VisualizationService
import org.springframework.http.HttpHeaders
import org.springframework.http.MediaType
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.*
import java.time.LocalDateTime
import java.time.format.DateTimeFormatter

@RestController
@RequestMapping("/api/v3/visualizations")
class VisualizationController(private val visualizationService: VisualizationService) {

    /**
     * Get a comprehensive report with multiple visualizations
     */
    @GetMapping("/report")
    fun getReport(
        @RequestParam(required = false) startTime: String?,
        @RequestParam(required = false) endTime: String?
    ): ResponseEntity<Map<String, Any>> {
        val timeRange = if (startTime != null && endTime != null) {
            TimeRange(
                LocalDateTime.parse(startTime, DateTimeFormatter.ISO_DATE_TIME),
                LocalDateTime.parse(endTime, DateTimeFormatter.ISO_DATE_TIME)
            )
        } else null

        return ResponseEntity.ok(visualizationService.generateReport(timeRange))
    }

    /**
     * Export vulnerability data as CSV
     */
    @GetMapping("/export/vulnerabilities")
    fun exportVulnerabilitiesCsv(
        @RequestParam(required = false) startTime: String?,
        @RequestParam(required = false) endTime: String?
    ): ResponseEntity<ByteArray> {
        val timeRange = if (startTime != null && endTime != null) {
            TimeRange(
                LocalDateTime.parse(startTime, DateTimeFormatter.ISO_DATE_TIME),
                LocalDateTime.parse(endTime, DateTimeFormatter.ISO_DATE_TIME)
            )
        } else null

        val csvData = visualizationService.exportVulnerabilitiesCsv(timeRange)
        
        return ResponseEntity.ok()
            .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=vulnerabilities.csv")
            .header(HttpHeaders.CONTENT_TYPE, MediaType.TEXT_PLAIN_VALUE)
            .body(csvData)
    }

    /**
     * Generate CSV content from the report data
     */
    private fun generateCsvFromReport(report: Map<String, Any>): String {
        val summary = report["summary"] as Map<String, Any>
        val vulnerabilityDistribution = report["vulnerabilityDistribution"] as Map<String, Any>
        val distributionData = vulnerabilityDistribution["data"] as Map<String, List<Any>>
        val vulnerabilityByCategory = report["vulnerabilityByCategory"] as Map<String, Any>
        val categoryData = vulnerabilityByCategory["data"] as Map<String, List<Any>>
        val assetRiskScore = report["assetRiskScore"] as Map<String, Any>
        val riskScoreData = assetRiskScore["data"] as Map<String, List<Any>>
        val vulnerabilityAge = report["vulnerabilityAgeDistribution"] as Map<String, Any>
        val ageData = vulnerabilityAge["data"] as Map<String, List<Any>>
        val remediationProgress = report["remediationProgress"] as Map<String, Any>
        val remediationData = remediationProgress["data"] as Map<String, List<Any>>
        
        return buildString {
            // Summary section
            appendLine("Security Posture Summary")
            appendLine("Metric,Value")
            appendLine("Total Vulnerabilities,${summary["totalVulnerabilities"]}")
            appendLine("Total Assets,${summary["totalAssets"]}")
            appendLine("Critical Vulnerabilities,${summary["criticalVulnerabilities"]}")
            appendLine("High Vulnerabilities,${summary["highVulnerabilities"]}")
            appendLine("Medium Vulnerabilities,${summary["mediumVulnerabilities"]}")
            appendLine("Low Vulnerabilities,${summary["lowVulnerabilities"]}")
            appendLine("Overall Risk Score,${summary["riskScore"]}")
            appendLine("Average Vulnerabilities per Asset,${summary["averageVulnerabilitiesPerAsset"]}")
            appendLine("Remediation Rate,${summary["remediationRate"]}")
            appendLine()
            
            // Vulnerability Distribution by Severity
            appendLine("Vulnerability Distribution by Severity")
            appendLine("Severity,Count")
            val labels = distributionData["labels"] as List<String>
            val values = distributionData["values"] as List<Int>
            labels.zip(values).forEach { (label, value) ->
                appendLine("$label,$value")
            }
            appendLine()
            
            // Vulnerability Categories
            appendLine("Top 10 Vulnerability Categories")
            appendLine("Category,Count")
            val categoryLabels = categoryData["labels"] as List<String>
            val categoryValues = categoryData["values"] as List<Int>
            categoryLabels.zip(categoryValues).forEach { (label, value) ->
                appendLine("$label,$value")
            }
            appendLine()
            
            // Asset Risk Score Distribution
            appendLine("Asset Risk Score Distribution")
            appendLine("Risk Score Range,Count")
            val riskLabels = riskScoreData["labels"] as List<String>
            val riskValues = riskScoreData["values"] as List<Int>
            riskLabels.zip(riskValues).forEach { (label, value) ->
                appendLine("$label,$value")
            }
            appendLine()
            
            // Vulnerability Age Distribution
            appendLine("Vulnerability Age Distribution")
            appendLine("Age Range,Count")
            val ageLabels = ageData["labels"] as List<String>
            val ageValues = ageData["values"] as List<Int>
            ageLabels.zip(ageValues).forEach { (label, value) ->
                appendLine("$label,$value")
            }
            appendLine()
            
            // Remediation Progress
            appendLine("Remediation Progress")
            appendLine("Status,Count")
            val remediationLabels = remediationData["labels"] as List<String>
            val remediationValues = remediationData["values"] as List<Int>
            remediationLabels.zip(remediationValues).forEach { (label, value) ->
                appendLine("$label,$value")
            }
        }
    }
} 