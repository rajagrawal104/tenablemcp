package com.tenable.mcp.client

import com.tenable.mcp.config.TenableConfig
import com.tenable.mcp.service.Severity
import com.tenable.mcp.service.TimeRange
import mu.KotlinLogging
import okhttp3.OkHttpClient
import okhttp3.Request
import org.springframework.stereotype.Component
import retrofit2.Retrofit
import retrofit2.converter.jackson.JacksonConverterFactory
import java.time.format.DateTimeFormatter
import java.util.concurrent.TimeUnit
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import com.fasterxml.jackson.module.kotlin.readValue
import com.fasterxml.jackson.module.kotlin.jacksonTypeRef
import io.ktor.client.*
import io.ktor.client.request.*
import io.ktor.client.statement.*
import io.ktor.http.*
import io.ktor.client.plugins.contentnegotiation.*
import io.ktor.serialization.kotlinx.json.*
import kotlinx.serialization.json.Json

private val logger = KotlinLogging.logger {}

/**
 * Client for interacting with the Tenable.io API
 * Handles authentication, request building, and response parsing
 */
@Component
class TenableClient(private val config: TenableConfig) {
    private val client = HttpClient {
        install(ContentNegotiation) {
            json(Json {
                ignoreUnknownKeys = true
                isLenient = true
            })
        }
    }

    private val baseUrl = config.baseUrl.trimEnd('/')

    /**
     * List vulnerabilities matching the specified criteria
     * @param severity Optional severity filter
     * @param timeRange Optional time range filter
     * @param cveId Optional CVE ID filter
     * @return Map containing the API response
     */
    fun listVulnerabilities(
        severity: Severity? = null,
        timeRange: TimeRange? = null,
        cveId: String? = null
    ): Map<String, Any> {
        val queryParams = mutableMapOf<String, String>()
        
        // Add optional filters to query parameters
        severity?.let { queryParams["severity"] = it.name.lowercase() }
        timeRange?.let {
            queryParams["start_time"] = it.start.format(DateTimeFormatter.ISO_DATE_TIME)
            queryParams["end_time"] = it.end.format(DateTimeFormatter.ISO_DATE_TIME)
        }
        cveId?.let { queryParams["cve_id"] = it }

        // Build and execute the request
        val request = Request.Builder()
            .url("$baseUrl/workbenches/vulnerabilities?${queryParams.toQueryString()}")
            .get()
            .build()

        return executeRequest(request)
    }

    /**
     * List assets matching the specified criteria
     * @param timeRange Optional time range filter
     * @param assetId Optional asset ID filter
     * @return Map containing the API response
     */
    fun listAssets(
        timeRange: TimeRange? = null,
        assetId: String? = null
    ): Map<String, Any> {
        val queryParams = mutableMapOf<String, String>()
        
        // Add optional filters to query parameters
        timeRange?.let {
            queryParams["start_time"] = it.start.format(DateTimeFormatter.ISO_DATE_TIME)
            queryParams["end_time"] = it.end.format(DateTimeFormatter.ISO_DATE_TIME)
        }
        assetId?.let { queryParams["asset_id"] = it }

        // Build and execute the request
        val request = Request.Builder()
            .url("$baseUrl/assets?${queryParams.toQueryString()}")
            .get()
            .build()

        return executeRequest(request)
    }

    /**
     * Export a report in the specified format
     * @param format Report format (default: json)
     * @param timeRange Optional time range filter
     * @return Map containing the API response
     */
    fun exportReport(
        format: String = "json",
        timeRange: TimeRange? = null
    ): Map<String, Any> {
        val queryParams = mutableMapOf(
            "format" to format
        )
        
        // Add optional time range filter
        timeRange?.let {
            queryParams["start_time"] = it.start.format(DateTimeFormatter.ISO_DATE_TIME)
            queryParams["end_time"] = it.end.format(DateTimeFormatter.ISO_DATE_TIME)
        }

        // Build and execute the request
        val request = Request.Builder()
            .url("$baseUrl/reports/export?${queryParams.toQueryString()}")
            .post(okhttp3.RequestBody.create(null, ByteArray(0)))
            .build()

        return executeRequest(request)
    }

    /**
     * Execute an HTTP request and parse the response
     * @param request The HTTP request to execute
     * @return Map containing the parsed JSON response
     * @throws RuntimeException if the request fails
     */
    private fun executeRequest(request: Request): Map<String, Any> {
        return try {
            client.newCall(request).execute().use { response ->
                // Check for successful response
                if (!response.isSuccessful) {
                    throw RuntimeException("API call failed: ${response.code} ${response.message}")
                }
                // Parse JSON response
                response.body?.string()?.let {
                    jacksonObjectMapper().readValue(it, jacksonTypeRef<Map<String, Any>>())
                } ?: emptyMap()
            }
        } catch (e: Exception) {
            logger.error(e) { "Failed to execute Tenable API request" }
            throw e
        }
    }

    /**
     * Convert a map of query parameters to a URL query string
     * @return URL-encoded query string
     */
    private fun Map<String, String>.toQueryString(): String {
        return entries.joinToString("&") { "${it.key}=${it.value}" }
    }

    fun listScans(timeRange: TimeRange? = null): Map<String, Any> {
        val url = "$baseUrl/scans"
        
        val response = client.get(url) {
            headers {
                append("X-ApiKeys", "accessKey=${config.accessKey};secretKey=${config.secretKey}")
                append("Accept", "application/json")
            }
            parameter("filter", "last_modification_date:${timeRange?.start ?: "0"}")
        }

        return if (response.status.isSuccess()) {
            val scans = response.body<Map<String, Any>>()["scans"] as? List<Map<String, Any>> ?: emptyList()
            mapOf("scans" to scans)
        } else {
            mapOf("error" to "Failed to list scans: ${response.status}")
        }
    }

    fun startScan(scanId: String? = null): Map<String, Any> {
        val url = if (scanId != null) {
            "$baseUrl/scans/$scanId/launch"
        } else {
            "$baseUrl/scans"
        }
        
        val response = if (scanId != null) {
            client.post(url) {
                headers {
                    append("X-ApiKeys", "accessKey=${config.accessKey};secretKey=${config.secretKey}")
                    append("Accept", "application/json")
                }
            }
        } else {
            client.post(url) {
                headers {
                    append("X-ApiKeys", "accessKey=${config.accessKey};secretKey=${config.secretKey}")
                    append("Accept", "application/json")
                    append("Content-Type", "application/json")
                }
                setBody(mapOf(
                    "name" to "MCP Automated Scan",
                    "targets" to "default",
                    "enabled" to true,
                    "schedule" to mapOf(
                        "type" to "once",
                        "start_time" to System.currentTimeMillis()
                    )
                ))
            }
        }

        return if (response.status.isSuccess()) {
            val scanUuid = response.body<Map<String, Any>>()["scan_uuid"] as? String
            mapOf(
                "success" to true,
                "scan_uuid" to scanUuid,
                "message" to "Scan started successfully"
            )
        } else {
            mapOf(
                "error" to "Failed to start scan: ${response.status}",
                "success" to false
            )
        }
    }

    fun getScanStatus(scanId: String): Map<String, Any> {
        val url = "$baseUrl/scans/$scanId"
        
        val response = client.get(url) {
            headers {
                append("X-ApiKeys", "accessKey=${config.accessKey};secretKey=${config.secretKey}")
                append("Accept", "application/json")
            }
        }

        return if (response.status.isSuccess()) {
            val scanInfo = response.body<Map<String, Any>>()
            mapOf(
                "status" to (scanInfo["status"] as? String ?: "unknown"),
                "scan_details" to scanInfo
            )
        } else {
            mapOf(
                "error" to "Failed to get scan status: ${response.status}",
                "status" to "error"
            )
        }
    }
} 