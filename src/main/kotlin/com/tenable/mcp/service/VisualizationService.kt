package com.tenable.mcp.service

import com.tenable.mcp.client.TenableClient
import com.tenable.mcp.model.TimeRange
import org.springframework.stereotype.Service
import java.time.LocalDateTime
import java.time.format.DateTimeFormatter

@Service
class VisualizationService(private val tenableClient: TenableClient) {

    /**
     * Generate a comprehensive report with multiple visualizations
     */
    fun generateReport(timeRange: TimeRange? = null): Map<String, Any> {
        val vulnerabilities = tenableClient.listVulnerabilities(timeRange = timeRange)
        val assets = tenableClient.listAssets(timeRange = timeRange)

        return mapOf(
            "summary" to generateSummary(vulnerabilities, assets),
            "vulnerabilityDistribution" to generateVulnerabilityDistribution(vulnerabilities),
            "assetVulnerabilityTrend" to generateAssetVulnerabilityTrend(vulnerabilities),
            "topVulnerableAssets" to generateTopVulnerableAssets(vulnerabilities),
            "severityTrend" to generateSeverityTrend(vulnerabilities),
            "vulnerabilityByCategory" to generateVulnerabilityByCategory(vulnerabilities),
            "assetRiskScore" to generateAssetRiskScore(assets),
            "vulnerabilityAgeDistribution" to generateVulnerabilityAgeDistribution(vulnerabilities),
            "remediationProgress" to generateRemediationProgress(vulnerabilities)
        )
    }

    /**
     * Generate a summary of the security posture
     */
    private fun generateSummary(vulnerabilities: Map<String, Any>, assets: Map<String, Any>): Map<String, Any> {
        val vulns = vulnerabilities["vulnerabilities"] as? List<Map<String, Any>> ?: emptyList()
        val assetList = assets["assets"] as? List<Map<String, Any>> ?: emptyList()

        val criticalVulns = vulns.count { it["severity"] == "Critical" }
        val highVulns = vulns.count { it["severity"] == "High" }
        val mediumVulns = vulns.count { it["severity"] == "Medium" }
        val lowVulns = vulns.count { it["severity"] == "Low" }

        return mapOf(
            "totalVulnerabilities" to vulns.size,
            "totalAssets" to assetList.size,
            "criticalVulnerabilities" to criticalVulns,
            "highVulnerabilities" to highVulns,
            "mediumVulnerabilities" to mediumVulns,
            "lowVulnerabilities" to lowVulns,
            "riskScore" to calculateRiskScore(criticalVulns, highVulns, mediumVulns, lowVulns),
            "averageVulnerabilitiesPerAsset" to if (assetList.isNotEmpty()) vulns.size.toDouble() / assetList.size else 0.0,
            "remediationRate" to calculateRemediationRate(vulns)
        )
    }

    /**
     * Calculate overall risk score based on vulnerability counts
     */
    private fun calculateRiskScore(critical: Int, high: Int, medium: Int, low: Int): Double {
        return (critical * 4.0 + high * 3.0 + medium * 2.0 + low * 1.0) / 
               (critical + high + medium + low).coerceAtLeast(1)
    }

    /**
     * Calculate remediation rate based on fixed vulnerabilities
     */
    private fun calculateRemediationRate(vulns: List<Map<String, Any>>): Double {
        val totalVulns = vulns.size
        val fixedVulns = vulns.count { it["status"] == "fixed" }
        return if (totalVulns > 0) fixedVulns.toDouble() / totalVulns else 0.0
    }

    /**
     * Generate vulnerability distribution by severity
     */
    private fun generateVulnerabilityDistribution(data: Map<String, Any>): Map<String, Any> {
        val vulns = data["vulnerabilities"] as? List<Map<String, Any>> ?: emptyList()
        val distribution = vulns.groupBy { it["severity"] as? String ?: "Unknown" }
            .mapValues { it.value.size }

        return mapOf(
            "type" to "pie",
            "data" to mapOf(
                "labels" to distribution.keys.toList(),
                "values" to distribution.values.toList(),
                "colors" to listOf("#FF0000", "#FFA500", "#FFFF00", "#00FF00") // Red, Orange, Yellow, Green
            )
        )
    }

    /**
     * Generate trend of vulnerabilities over time
     */
    private fun generateAssetVulnerabilityTrend(data: Map<String, Any>): Map<String, Any> {
        val vulns = data["vulnerabilities"] as? List<Map<String, Any>> ?: emptyList()
        val trend = vulns.groupBy { 
            (it["discovered_at"] as? String)?.substring(0, 10) ?: "Unknown" 
        }.mapValues { it.value.size }

        return mapOf(
            "type" to "line",
            "data" to mapOf(
                "labels" to trend.keys.toList(),
                "values" to trend.values.toList(),
                "title" to "Vulnerability Trend Over Time"
            )
        )
    }

    /**
     * Generate list of top vulnerable assets
     */
    private fun generateTopVulnerableAssets(data: Map<String, Any>): Map<String, Any> {
        val vulns = data["vulnerabilities"] as? List<Map<String, Any>> ?: emptyList()
        val assetVulns = vulns.groupBy { it["asset_name"] as? String ?: "Unknown" }
            .mapValues { it.value.size }
            .toList()
            .sortedByDescending { it.second }
            .take(10)

        return mapOf(
            "type" to "bar",
            "data" to mapOf(
                "labels" to assetVulns.map { it.first },
                "values" to assetVulns.map { it.second },
                "title" to "Top 10 Most Vulnerable Assets"
            )
        )
    }

    /**
     * Generate trend of vulnerabilities by severity over time
     */
    private fun generateSeverityTrend(data: Map<String, Any>): Map<String, Any> {
        val vulns = data["vulnerabilities"] as? List<Map<String, Any>> ?: emptyList()
        val severityTrend = vulns.groupBy { 
            Triple(
                (it["discovered_at"] as? String)?.substring(0, 10) ?: "Unknown",
                it["severity"] as? String ?: "Unknown",
                1
            )
        }.mapValues { it.value.size }

        val dates = severityTrend.keys.map { it.first }.distinct().sorted()
        val severities = severityTrend.keys.map { it.second }.distinct()

        val series = severities.map { severity ->
            mapOf(
                "name" to severity,
                "data" to dates.map { date ->
                    severityTrend[Triple(date, severity, 1)] ?: 0
                }
            )
        }

        return mapOf(
            "type" to "line",
            "data" to mapOf(
                "labels" to dates,
                "series" to series,
                "title" to "Vulnerability Severity Trend"
            )
        )
    }

    /**
     * Generate vulnerability distribution by category
     */
    private fun generateVulnerabilityByCategory(data: Map<String, Any>): Map<String, Any> {
        val vulns = data["vulnerabilities"] as? List<Map<String, Any>> ?: emptyList()
        val categoryDistribution = vulns.groupBy { it["category"] as? String ?: "Unknown" }
            .mapValues { it.value.size }
            .toList()
            .sortedByDescending { it.second }
            .take(10)

        return mapOf(
            "type" to "horizontalBar",
            "data" to mapOf(
                "labels" to categoryDistribution.map { it.first },
                "values" to categoryDistribution.map { it.second },
                "title" to "Top 10 Vulnerability Categories"
            )
        )
    }

    /**
     * Generate asset risk score distribution
     */
    private fun generateAssetRiskScore(data: Map<String, Any>): Map<String, Any> {
        val assets = data["assets"] as? List<Map<String, Any>> ?: emptyList()
        val riskScores = assets.map { it["risk_score"] as? Double ?: 0.0 }
        
        val ranges = listOf(
            "0-20" to 0,
            "21-40" to 0,
            "41-60" to 0,
            "61-80" to 0,
            "81-100" to 0
        ).toMutableList()

        riskScores.forEach { score ->
            when {
                score <= 20 -> ranges[0] = ranges[0].copy(second = ranges[0].second + 1)
                score <= 40 -> ranges[1] = ranges[1].copy(second = ranges[1].second + 1)
                score <= 60 -> ranges[2] = ranges[2].copy(second = ranges[2].second + 1)
                score <= 80 -> ranges[3] = ranges[3].copy(second = ranges[3].second + 1)
                else -> ranges[4] = ranges[4].copy(second = ranges[4].second + 1)
            }
        }

        return mapOf(
            "type" to "bar",
            "data" to mapOf(
                "labels" to ranges.map { it.first },
                "values" to ranges.map { it.second },
                "title" to "Asset Risk Score Distribution"
            )
        )
    }

    /**
     * Generate vulnerability age distribution
     */
    private fun generateVulnerabilityAgeDistribution(data: Map<String, Any>): Map<String, Any> {
        val vulns = data["vulnerabilities"] as? List<Map<String, Any>> ?: emptyList()
        val now = LocalDateTime.now()
        
        val ageRanges = listOf(
            "0-7 days" to 0,
            "8-30 days" to 0,
            "31-90 days" to 0,
            "91-180 days" to 0,
            ">180 days" to 0
        ).toMutableList()

        vulns.forEach { vuln ->
            val discoveredAt = (vuln["discovered_at"] as? String)?.let {
                LocalDateTime.parse(it, DateTimeFormatter.ISO_DATE_TIME)
            } ?: now
            
            val daysOld = java.time.Duration.between(discoveredAt, now).toDays()
            
            when {
                daysOld <= 7 -> ageRanges[0] = ageRanges[0].copy(second = ageRanges[0].second + 1)
                daysOld <= 30 -> ageRanges[1] = ageRanges[1].copy(second = ageRanges[1].second + 1)
                daysOld <= 90 -> ageRanges[2] = ageRanges[2].copy(second = ageRanges[2].second + 1)
                daysOld <= 180 -> ageRanges[3] = ageRanges[3].copy(second = ageRanges[3].second + 1)
                else -> ageRanges[4] = ageRanges[4].copy(second = ageRanges[4].second + 1)
            }
        }

        return mapOf(
            "type" to "pie",
            "data" to mapOf(
                "labels" to ageRanges.map { it.first },
                "values" to ageRanges.map { it.second },
                "title" to "Vulnerability Age Distribution"
            )
        )
    }

    /**
     * Generate remediation progress visualization
     */
    private fun generateRemediationProgress(data: Map<String, Any>): Map<String, Any> {
        val vulns = data["vulnerabilities"] as? List<Map<String, Any>> ?: emptyList()
        val total = vulns.size
        val fixed = vulns.count { it["status"] == "fixed" }
        val inProgress = vulns.count { it["status"] == "in_progress" }
        val open = total - fixed - inProgress

        return mapOf(
            "type" to "doughnut",
            "data" to mapOf(
                "labels" to listOf("Fixed", "In Progress", "Open"),
                "values" to listOf(fixed, inProgress, open),
                "title" to "Remediation Progress"
            )
        )
    }

    /**
     * Export vulnerability data as CSV
     */
    fun exportVulnerabilitiesCsv(timeRange: TimeRange? = null): ByteArray {
        val report = generateReport(timeRange)
        return generateCsvFromReport(report).toByteArray()
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