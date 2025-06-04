package com.tenable.mcp.controller

import com.tenable.mcp.config.TenableConfig
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.*

@RestController
@RequestMapping("/api/config")
class ConfigController(private val tenableConfig: TenableConfig) {

    @PostMapping
    fun updateConfig(@RequestBody config: Map<String, String>): ResponseEntity<Map<String, Any>> {
        return try {
            config["accessKey"]?.let { tenableConfig.accessKey = it }
            config["secretKey"]?.let { tenableConfig.secretKey = it }
            config["baseUrl"]?.let { tenableConfig.baseUrl = it }
            ResponseEntity.ok(mapOf(
                "success" to true,
                "message" to "Configuration updated successfully"
            ) as Map<String, Any>)
        } catch (e: Exception) {
            ResponseEntity.badRequest().body(mapOf(
                "success" to false,
                "message" to (e.message ?: "Unknown error occurred")
            ) as Map<String, Any>)
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
} 