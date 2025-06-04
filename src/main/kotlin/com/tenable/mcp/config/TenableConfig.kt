package com.tenable.mcp.config

import org.springframework.boot.context.properties.ConfigurationProperties
import org.springframework.context.annotation.Configuration

/**
 * Configuration class for Tenable.io API settings
 * Properties are loaded from application.yml and can be overridden by environment variables
 */
@Configuration
@ConfigurationProperties(prefix = "tenable")
data class TenableConfig(
    var accessKey: String = "",        // Tenable.io Access key
    var secretKey: String = "",        // Tenable.io Secret key
    var baseUrl: String = "https://cloud.tenable.com",  // Tenable.io API base URL
    var timeout: Int = 30000,          // API request timeout in milliseconds
    var maxRetries: Int = 3            // Maximum number of retry attempts for failed requests
) 