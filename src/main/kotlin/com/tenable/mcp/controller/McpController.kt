package com.tenable.mcp.controller

import com.tenable.mcp.client.TenableClient
import com.tenable.mcp.service.IntentClassifier
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController
import com.tenable.mcp.model.Severity
import com.tenable.mcp.model.TimeRange
import com.tenable.mcp.model.Action
import com.tenable.mcp.model.ConversationContext
import com.tenable.mcp.model.Message
import com.tenable.mcp.model.Intent
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import org.springframework.http.ResponseEntity
import java.time.LocalDateTime

// Request DTO for the /ask endpoint
data class AskRequest(
    val prompt: String,
    val context: ConversationContext? = null
)

// Response DTO containing both raw API response and a human-readable summary
data class AskResponse(
    val rawResponse: Map<String, Any>,  // Raw JSON response from Tenable API
    val summary: String,                // Human-readable summary of the response
    val action: String? = null,         // The action taken
    val filters: Map<String, Any>? = null  // Any filters applied
)

/**
 * REST controller for handling natural language queries to Tenable.io
 * Provides a single endpoint that accepts prompts and returns processed results
 */
@RestController
@RequestMapping("/api")
class McpController(
    private val intentClassifier: IntentClassifier,  // Service for analyzing user prompts
    private val tenableClient: TenableClient        // Client for Tenable.io API calls
) {
    private val logger: Logger = LoggerFactory.getLogger(this::class.java)

    /**
     * Process a natural language prompt and return relevant Tenable.io data
     * @param request The user's prompt wrapped in an AskRequest
     * @return AskResponse containing both raw data and a summary
     */
    @PostMapping("/ask")
    fun ask(@RequestBody request: AskRequest): ResponseEntity<AskResponse> {
        try {
            // Analyze the prompt to determine the user's intent
            val intent = intentClassifier.classifyIntent(request.prompt, request.context)
            
            // Execute the appropriate API call based on the intent
            val rawResponse = when (intent.action) {
                Action.LIST_VULNERABILITIES -> {
                    val vulnerabilities = tenableClient.listVulnerabilities(
                        severity = intent.severity,
                        timeRange = intent.timeRange,
                        cveId = intent.cveId
                    )
                    mapOf(
                        "vulnerabilities" to vulnerabilities,
                        "action" to "list_vulnerabilities",
                        "filters" to mapOf(
                            "severity" to intent.severity?.name,
                            "timeRange" to intent.timeRange?.let { "${it.start} to ${it.end}" },
                            "cveId" to intent.cveId
                        )
                    )
                }
                Action.LIST_ASSETS -> {
                    val assets = tenableClient.getAssets(
                        timeRange = intent.timeRange,
                        assetId = intent.assetId
                    )
                    mapOf(
                        "assets" to assets,
                        "action" to "list_assets",
                        "filters" to mapOf(
                            "timeRange" to intent.timeRange?.let { "${it.start} to ${it.end}" },
                            "assetId" to intent.assetId
                        )
                    )
                }
                Action.LIST_SCANS -> {
                    val scans = tenableClient.getScans(
                        timeRange = intent.timeRange,
                        scanId = intent.scanId
                    )
                    mapOf(
                        "scans" to scans,
                        "action" to "list_scans",
                        "filters" to mapOf(
                            "timeRange" to intent.timeRange?.let { "${it.start} to ${it.end}" },
                            "scanId" to intent.scanId
                        )
                    )
                }
                Action.EXPORT_VULNERABILITIES -> {
                    val vulnerabilities = tenableClient.getVulnerabilities(
                        severity = intent.severity,
                        timeRange = intent.timeRange,
                        cveId = intent.cveId
                    )
                    mapOf(
                        "vulnerabilities" to vulnerabilities,
                        "action" to "export_vulnerabilities",
                        "filters" to mapOf(
                            "severity" to intent.severity?.name,
                            "timeRange" to intent.timeRange?.let { "${it.start} to ${it.end}" },
                            "cveId" to intent.cveId
                        )
                    )
                }
                Action.EXPORT_ASSETS -> {
                    val assets = tenableClient.getAssets(
                        timeRange = intent.timeRange,
                        assetId = intent.assetId
                    )
                    mapOf(
                        "assets" to assets,
                        "action" to "export_assets",
                        "filters" to mapOf(
                            "timeRange" to intent.timeRange?.let { "${it.start} to ${it.end}" },
                            "assetId" to intent.assetId
                        )
                    )
                }
                Action.EXPORT_SCANS -> {
                    val scans = tenableClient.getScans(
                        timeRange = intent.timeRange,
                        scanId = intent.scanId
                    )
                    mapOf(
                        "scans" to scans,
                        "action" to "export_scans",
                        "filters" to mapOf(
                            "timeRange" to intent.timeRange?.let { "${it.start} to ${it.end}" },
                            "scanId" to intent.scanId
                        )
                    )
                }
                Action.START_SCAN -> {
                    if (intent.scanId == null) {
                        mapOf(
                            "error" to "Scan ID is required to start a scan",
                            "action" to "start_scan"
                        )
                    } else {
                        val scanResponse = tenableClient.startScan(intent.scanId)
                        mapOf(
                            "scan" to scanResponse,
                            "action" to "start_scan",
                            "scanId" to intent.scanId
                        )
                    }
                }
                else -> mapOf("error" to "Could not determine the intent from the prompt")
            }

            // Generate a human-readable summary of the response
            val summary = generateSummary(intent, rawResponse)
            
            return ResponseEntity.ok(AskResponse(
                rawResponse = rawResponse,
                summary = summary,
                action = rawResponse["action"] as? String,
                filters = rawResponse["filters"] as? Map<String, Any>
            ))
        } catch (e: Exception) {
            logger.error("Error processing request: ${request.prompt}", e)
            val errorMessage = e.message ?: "An unknown error occurred"
            return ResponseEntity.badRequest().body(AskResponse(
                rawResponse = mapOf("error" to errorMessage),
                summary = "Error: $errorMessage"
            ))
        }
    }

    /**
     * Generate a human-readable summary of the API response
     * @param intent The extracted intent from the user's prompt
     * @param response The raw API response
     * @return A formatted string summarizing the response
     */
    private fun generateSummary(intent: Intent, response: Map<String, Any>): String {
        return when (intent.action) {
            Action.LIST_VULNERABILITIES -> {
                val vulns = response["vulnerabilities"] as? List<Map<String, Any>>
                buildString {
                    appendLine("Found ${vulns?.size ?: 0} vulnerabilities")
                    if (vulns?.isNotEmpty() == true) {
                        appendLine("\nSeverity Distribution:")
                        val severityCounts = vulns.groupBy { it["severity"] as? String ?: "Unknown" }
                            .mapValues { it.value.size }
                        severityCounts.forEach { (severity, count) ->
                            appendLine("$severity: $count")
                        }
                    }
                    intent.severity?.let { appendLine("\nFiltered by severity: ${it.name}") }
                    intent.timeRange?.let { 
                        appendLine("Time range: ${it.start} to ${it.end}")
                    }
                    intent.cveId?.let { appendLine("CVE: $it") }
                }
            }
            Action.LIST_ASSETS -> {
                val assets = response["assets"] as? List<Map<String, Any>>
                buildString {
                    appendLine("Found ${assets?.size ?: 0} assets")
                    intent.timeRange?.let { 
                        appendLine("Time range: ${it.start} to ${it.end}")
                    }
                    intent.assetId?.let { appendLine("Asset ID: $it") }
                }
            }
            Action.LIST_SCANS -> {
                val scans = response["scans"] as? List<Map<String, Any>>
                buildString {
                    appendLine("Found ${scans?.size ?: 0} scans")
                    intent.timeRange?.let { 
                        appendLine("Time range: ${it.start} to ${it.end}")
                    }
                    // Add scan status summary if available
                    scans?.let { scanList ->
                        val statusCounts = scanList.groupBy { it["status"] as? String ?: "Unknown" }
                            .mapValues { it.value.size }
                        appendLine("\nScan Status Summary:")
                        statusCounts.forEach { (status, count) ->
                            appendLine("$status: $count")
                        }
                    }
                }
            }
            Action.EXPORT_VULNERABILITIES, Action.EXPORT_ASSETS -> {
                "Report exported successfully"
            }
            Action.EXPORT_SCANS -> {
                val scans = response["scans"] as? List<Map<String, Any>>
                buildString {
                    appendLine("Exported ${scans?.size ?: 0} scans")
                    intent.timeRange?.let { 
                        appendLine("Time range: ${it.start} to ${it.end}")
                    }
                    appendLine("\nThe data is ready for download.")
                }
            }
            Action.START_SCAN -> {
                val scanResponse = response["scan"] as? Map<String, Any>
                if (scanResponse?.get("success") == true) {
                    buildString {
                        appendLine("Scan started successfully")
                        scanResponse["scan_uuid"]?.let { appendLine("Scan UUID: $it") }
                        intent.scanId?.let { appendLine("Scan ID: $it") }
                    }
                } else {
                    "Failed to start scan: ${scanResponse?.get("error") ?: "Unknown error"}"
                }
            }
            else -> {
                response["error"]?.toString() ?: "Could not process the request. Please try rephrasing your question."
            }
        }
    }
} 