package com.tenable.mcp.controller

import com.tenable.mcp.config.TenableConfig
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.*
import okhttp3.OkHttpClient
import okhttp3.Request
import java.util.concurrent.TimeUnit
import org.slf4j.LoggerFactory

@RestController
@RequestMapping("/api/config")
class ConfigController(private val tenableConfig: TenableConfig) {
    private val logger = LoggerFactory.getLogger(ConfigController::class.java)

    @PostMapping
    fun updateConfig(@RequestBody config: Map<String, String>): ResponseEntity<Map<String, Any>> {
        return try {
            config["accessKey"]?.let { tenableConfig.accessKey = it }
            config["secretKey"]?.let { tenableConfig.secretKey = it }
            config["baseUrl"]?.let { tenableConfig.baseUrl = it }
            ResponseEntity.ok(mapOf(
                "success" to true,
                "message" to "Configuration updated successfully"
            ))
        } catch (e: Exception) {
            ResponseEntity.badRequest().body(mapOf(
                "success" to false,
                "message" to (e.message ?: "Unknown error occurred")
            ))
        }
    }

    @GetMapping
    fun getConfig(): ResponseEntity<Map<String, Any>> {
        return ResponseEntity.ok(mapOf(
            "success" to true,
            "config" to mapOf(
                "baseUrl" to tenableConfig.baseUrl,
                "timeout" to tenableConfig.timeout,
                "maxRetries" to tenableConfig.maxRetries,
                "hasAccessKey" to tenableConfig.accessKey.isNotEmpty(),
                "hasSecretKey" to tenableConfig.secretKey.isNotEmpty()
            )
        ))
    }

    @PostMapping("/test-connection")
    fun testConnection(): ResponseEntity<Map<String, Any>> {
        return try {
            val client = OkHttpClient.Builder()
                .connectTimeout(10, TimeUnit.SECONDS)
                .readTimeout(10, TimeUnit.SECONDS)
                .build()

            val url = "${tenableConfig.baseUrl}/assets"
            logger.debug("Testing connection to: $url")
            logger.debug("Using access key: ${tenableConfig.accessKey.take(4)}...")
            
            val request = Request.Builder()
                .url(url)
                .addHeader("X-ApiKeys", "accessKey=${tenableConfig.accessKey};secretKey=${tenableConfig.secretKey}")
                .addHeader("Accept", "application/json")
                .addHeader("Content-Type", "application/json")
                .get()
                .build()

            client.newCall(request).execute().use { response ->
                val responseBody = response.body?.string()
                logger.debug("Response status: ${response.code}")
                logger.debug("Response body: $responseBody")
                
                if (response.isSuccessful) {
                    ResponseEntity.ok(mapOf(
                        "success" to true,
                        "message" to "Successfully connected to Tenable.io",
                        "status" to (response.code as Int),
                        "details" to "Credentials are valid and connection is working"
                    ))
                } else {
                    val details: String = when (response.code) {
                        401 -> "Invalid credentials (Access Key or Secret Key)"
                        403 -> "Insufficient permissions. Please ensure your API keys have asset access."
                        404 -> "API endpoint not found"
                        else -> "Connection failed with status ${response.code}. Response: $responseBody"
                    }
                    logger.error("Connection failed: $details")
                    ResponseEntity.badRequest().body(mapOf(
                        "success" to false,
                        "message" to "Failed to connect to Tenable.io",
                        "status" to (response.code as Int),
                        "details" to details
                    ))
                }
            }
        } catch (e: Exception) {
            logger.error("Exception during connection test", e)
            ResponseEntity.badRequest().body(mapOf(
                "success" to false,
                "message" to "Connection test failed",
                "details" to (e.message?.toString() ?: "Unknown error occurred")
            ))
        }
    }
} 