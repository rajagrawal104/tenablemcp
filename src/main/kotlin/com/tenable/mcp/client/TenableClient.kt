package com.tenable.mcp.client

import com.tenable.mcp.config.TenableConfig
import com.tenable.mcp.model.Severity
import com.tenable.mcp.model.TimeRange
import com.tenable.mcp.model.Action
import mu.KotlinLogging
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.MediaType.Companion.toMediaTypeOrNull
import okhttp3.RequestBody.Companion.toRequestBody
import org.springframework.stereotype.Component
import java.time.format.DateTimeFormatter
import java.util.concurrent.TimeUnit
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import com.fasterxml.jackson.module.kotlin.readValue
import com.fasterxml.jackson.module.kotlin.jacksonTypeRef
import org.springframework.beans.factory.annotation.Value
import org.springframework.http.*
import org.springframework.web.client.RestTemplate

private val logger = KotlinLogging.logger {}

/**
 * Client for interacting with the Tenable.io API
 * Handles authentication, request building, and response parsing
 */
@Component
class TenableClient(
    @Value("\${tenable.api.url}") private val apiUrl: String,
    @Value("\${tenable.api.key}") private val apiKey: String,
    @Value("\${tenable.api.secret}") private val apiSecret: String
) {
    private val restTemplate = RestTemplate()
    private val formatter = DateTimeFormatter.ISO_DATE_TIME

    private val client: OkHttpClient = OkHttpClient.Builder()
        .addInterceptor { chain ->
            val request = chain.request().newBuilder()
                .addHeader("X-ApiKeys", "accessKey=$apiKey;secretKey=$apiSecret")
                .addHeader("Accept", "application/json")
                .addHeader("Content-Type", "application/json")
                .build()
            chain.proceed(request)
        }
        .connectTimeout(30, TimeUnit.SECONDS)
        .readTimeout(30, TimeUnit.SECONDS)
        .build()

    private val baseUrl = apiUrl.trimEnd('/')

    /**
     * List vulnerabilities matching the specified criteria
     * @param severity Optional severity filter
     * @param timeRange Optional time range filter
     * @param cveId Optional CVE ID filter
     * @return List of vulnerability maps
     */
    fun listVulnerabilities(
        severity: Severity? = null,
        timeRange: TimeRange? = null,
        cveId: String? = null
    ): List<Map<String, Any>> {
        val queryParams = mutableMapOf<String, String>()
        
        // Add optional filters to query parameters
        severity?.let { queryParams["severity"] = it.name.lowercase() }
        timeRange?.let {
            queryParams["start_time"] = it.start.format(formatter)
            queryParams["end_time"] = it.end.format(formatter)
        }
        cveId?.let { queryParams["cve_id"] = it }

        // Build and execute the request
        val request = Request.Builder()
            .url("$baseUrl/workbenches/vulnerabilities?${queryParams.toQueryString()}")
            .get()
            .build()

        val response = executeRequest(request)
        return (response["vulnerabilities"] as? List<Map<String, Any>>) ?: emptyList()
    }

    /**
     * List assets matching the specified criteria
     * @param timeRange Optional time range filter
     * @param assetId Optional asset ID filter
     * @return List of asset maps
     */
    fun listAssets(
        timeRange: TimeRange? = null,
        assetId: String? = null
    ): List<Map<String, Any>> {
        val queryParams = mutableMapOf<String, String>()
        
        // Add optional filters to query parameters
        timeRange?.let {
            queryParams["start_time"] = it.start.format(formatter)
            queryParams["end_time"] = it.end.format(formatter)
        }
        assetId?.let { queryParams["asset_id"] = it }

        // Build and execute the request
        val request = Request.Builder()
            .url("$baseUrl/assets?${queryParams.toQueryString()}")
            .get()
            .build()

        val response = executeRequest(request)
        return (response["assets"] as? List<Map<String, Any>>) ?: emptyList()
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
            queryParams["start_time"] = it.start.format(formatter)
            queryParams["end_time"] = it.end.format(formatter)
        }

        // Build and execute the request
        val request = Request.Builder()
            .url("$baseUrl/reports/export?${queryParams.toQueryString()}")
            .post(ByteArray(0).toRequestBody(null, 0, 0))
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
        return entries.filter { it.value.isNotBlank() }
            .joinToString("&") { "${it.key}=${it.value}" }
    }

    fun getVulnerabilities(
        severity: Severity? = null,
        timeRange: TimeRange? = null,
        cveId: String? = null
    ): List<Map<String, Any>> {
        val headers = createHeaders()
        val url = "$baseUrl/vulnerabilities"
        
        val params = mutableMapOf<String, String>()
        severity?.let { params["severity"] = it.name.lowercase() }
        timeRange?.let {
            params["start_time"] = it.start.format(formatter)
            params["end_time"] = it.end.format(formatter)
        }
        cveId?.let { params["cve_id"] = it }

        val response = restTemplate.exchange(
            url,
            HttpMethod.GET,
            HttpEntity(null, headers),
            Map::class.java,
            params
        )

        return (response.body?.get("vulnerabilities") as? List<Map<String, Any>>) ?: emptyList()
    }

    fun getAssets(
        timeRange: TimeRange? = null,
        assetId: String? = null
    ): List<Map<String, Any>> {
        val headers = createHeaders()
        val url = "$baseUrl/assets"
        
        val params = mutableMapOf<String, String>()
        timeRange?.let {
            params["start_time"] = it.start.format(formatter)
            params["end_time"] = it.end.format(formatter)
        }
        assetId?.let { params["asset_id"] = it }

        val response = restTemplate.exchange(
            url,
            HttpMethod.GET,
            HttpEntity(null, headers),
            Map::class.java,
            params
        )

        return (response.body?.get("assets") as? List<Map<String, Any>>) ?: emptyList()
    }

    fun getScans(
        timeRange: TimeRange? = null,
        scanId: String? = null
    ): List<Map<String, Any>> {
        val headers = createHeaders()
        val url = "$baseUrl/scans"
        
        val params = mutableMapOf<String, String>()
        timeRange?.let {
            params["start_time"] = it.start.format(formatter)
            params["end_time"] = it.end.format(formatter)
        }
        scanId?.let { params["scan_id"] = it }

        val response = restTemplate.exchange(
            url,
            HttpMethod.GET,
            HttpEntity(null, headers),
            Map::class.java,
            params
        )

        return (response.body?.get("scans") as? List<Map<String, Any>>) ?: emptyList()
    }

    fun startScan(scanId: String): Map<String, Any> {
        val headers = createHeaders()
        val url = "$baseUrl/scans/$scanId/launch"

        val response = restTemplate.exchange(
            url,
            HttpMethod.POST,
            HttpEntity(null, headers),
            Map::class.java
        )

        // Ensure the return type is Map<String, Any> with non-null values
        return response.body?.entries
            ?.filter { it.key is String && it.value != null }
            ?.associate { it.key as String to it.value!! } ?: mapOf("error" to "Failed to start scan")
    }

    private fun createHeaders(): HttpHeaders {
        return HttpHeaders().apply {
            set("X-ApiKeys", "accessKey=$apiKey;secretKey=$apiSecret")
            contentType = MediaType.APPLICATION_JSON
        }
    }
} 