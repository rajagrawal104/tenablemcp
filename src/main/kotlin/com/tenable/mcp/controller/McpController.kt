package com.tenable.mcp.controller

import com.tenable.mcp.client.TenableClient
import com.tenable.mcp.service.IntentClassifier
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController
import com.tenable.mcp.service.Action
import com.tenable.mcp.service.Intent
import com.tenable.mcp.service.Severity
import com.tenable.mcp.service.TimeRange

// Request DTO for the /ask endpoint
data class AskRequest(val prompt: String)

// Response DTO containing both raw API response and a human-readable summary
data class AskResponse(
    val rawResponse: Map<String, Any>,  // Raw JSON response from Tenable API
    val summary: String                 // Human-readable summary of the response
)

/**
 * REST controller for handling natural language queries to Tenable.io
 * Provides a single endpoint that accepts prompts and returns processed results
 */
@RestController
@RequestMapping("/api/v1")
class McpController(
    private val intentClassifier: IntentClassifier,  // Service for analyzing user prompts
    private val tenableClient: TenableClient        // Client for Tenable.io API calls
) {
    /**
     * Process a natural language prompt and return relevant Tenable.io data
     * @param request The user's prompt wrapped in an AskRequest
     * @return AskResponse containing both raw data and a summary
     */
    @PostMapping("/ask")
    fun ask(@RequestBody request: AskRequest): AskResponse {
        // Analyze the prompt to determine the user's intent
        val intent = intentClassifier.classifyIntent(request.prompt)
        
        // Execute the appropriate API call based on the intent
        val rawResponse = when (intent.action) {
            Action.LIST_VULNERABILITIES -> tenableClient.listVulnerabilities(
                severity = intent.severity,
                timeRange = intent.timeRange,
                cveId = intent.cveId
            )
            Action.LIST_ASSETS -> tenableClient.listAssets(
                timeRange = intent.timeRange,
                assetId = intent.assetId
            )
            Action.EXPORT_VULNERABILITIES, Action.EXPORT_ASSETS -> tenableClient.exportReport(
                timeRange = intent.timeRange
            )
            else -> mapOf("error" to "Could not determine the intent from the prompt")
        }

        // Generate a human-readable summary of the response
        val summary = generateSummary(intent, rawResponse)
        
        return AskResponse(rawResponse, summary)
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
                    intent.severity?.let { appendLine("Severity: ${it.name}") }
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
            Action.EXPORT_VULNERABILITIES, Action.EXPORT_ASSETS -> {
                "Report exported successfully"
            }
            else -> {
                "Could not process the request. Please try rephrasing your question."
            }
        }
    }
} 