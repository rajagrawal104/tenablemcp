# Tenable MCP (Management Control Panel)

A Spring Boot application that provides a comprehensive interface for managing and visualizing Tenable.io security data.

## Features

- **Configuration Management**
  - Easy configuration of Tenable.io API credentials
  - Support for custom API endpoints
  - Configurable timeouts and retry policies

- **Security Visualization**
  - Vulnerability distribution by severity
  - Asset vulnerability trends
  - Top vulnerable assets analysis
  - Vulnerability age distribution
  - Remediation progress tracking
  - Asset risk score distribution
  - Vulnerability category analysis

- **Reporting**
  - Comprehensive CSV exports
  - Detailed security posture summaries
  - Customizable time range filtering

## Prerequisites

- Java 17 or later
- Gradle 7.x or later (included in the project)
- Docker (optional, for containerized deployment)
- Tenable.io API credentials

## Quick Start

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/tenablemcp.git
   cd tenablemcp
   ```

2. Run the setup script:
   ```bash
   chmod +x setup.sh
   ./setup.sh
   ```

3. Update the configuration:
   Edit `src/main/resources/application.yml` with your Tenable.io credentials:
   ```yaml
   tenable:
     apiKey: "your-api-key"
     accessKey: "your-access-key"
     secretKey: "your-secret-key"
     baseUrl: "https://cloud.tenable.com"
   ```

4. Run the application:
   ```bash
   ./gradlew bootRun
   ```

## Running with Docker

1. Build the Docker image:
   ```bash
   docker build -t tenable-mcp .
   ```

2. Run the container:
   ```bash
   docker run -p 8080:8080 tenable-mcp
   ```

## API Endpoints

### Configuration

- `GET /api/config`
  - Get current configuration
  - Response: Current configuration settings

- `POST /api/config`
  - Update configuration
  - Body: JSON with configuration parameters
  - Example:
    ```json
    {
      "accessKey": "your-access-key",
      "secretKey": "your-secret-key",
      "baseUrl": "https://cloud.tenable.com"
    }
    ```

### Visualizations

- `GET /api/v1/visualizations/report`
  - Get comprehensive security report
  - Query Parameters:
    - `startTime` (optional): ISO-8601 formatted start time
    - `endTime` (optional): ISO-8601 formatted end time
  - Response: JSON containing multiple visualizations

- `GET /api/v1/visualizations/export/vulnerabilities`
  - Export report as CSV
  - Query Parameters:
    - `startTime` (optional): ISO-8601 formatted start time
    - `endTime` (optional): ISO-8601 formatted end time
  - Response: CSV file download

## Visualization Types

1. **Vulnerability Distribution**
   - Pie chart showing distribution by severity
   - Color-coded for easy interpretation

2. **Asset Vulnerability Trend**
   - Line chart showing vulnerability trends over time
   - Helps track security posture improvements

3. **Top Vulnerable Assets**
   - Bar chart of most vulnerable assets
   - Helps prioritize remediation efforts

4. **Vulnerability Age Distribution**
   - Pie chart showing age ranges of vulnerabilities
   - Helps identify stale vulnerabilities

5. **Remediation Progress**
   - Doughnut chart showing fixed vs. open vulnerabilities
   - Tracks remediation effectiveness

6. **Asset Risk Score Distribution**
   - Bar chart showing distribution of asset risk scores
   - Helps identify high-risk assets

## Development

### Project Structure

```
src/main/kotlin/com/tenable/mcp/
├── config/         # Configuration classes
├── controller/     # REST controllers
├── service/        # Business logic
├── client/         # Tenable.io API client
└── model/          # Data models
```

### Building

```bash
./gradlew clean build
```

### Running Tests

```bash
./gradlew test
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Support

For support, please open an issue in the GitHub repository or contact the maintainers. 