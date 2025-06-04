#!/bin/bash

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}Setting up Tenable MCP Project...${NC}"

# Check if Java 17 is installed
if ! command -v java &> /dev/null; then
    echo -e "${RED}Java is not installed. Please install Java 17 or later.${NC}"
    exit 1
fi

java_version=$(java -version 2>&1 | awk -F '"' '/version/ {print $2}')
if [[ "$java_version" < "17" ]]; then
    echo -e "${RED}Java version $java_version is not supported. Please install Java 17 or later.${NC}"
    exit 1
fi

echo -e "${GREEN}Java version $java_version detected.${NC}"

# Check if Docker is installed (optional)
if command -v docker &> /dev/null; then
    echo -e "${GREEN}Docker detected. You can use Docker to run the application.${NC}"
else
    echo -e "${YELLOW}Docker not detected. You can still run the application without Docker.${NC}"
fi

# Create application.yml if it doesn't exist
if [ ! -f "src/main/resources/application.yml" ]; then
    echo -e "${YELLOW}Creating application.yml...${NC}"
    cat > src/main/resources/application.yml << EOL
tenable:
  apiKey: ""
  accessKey: ""
  secretKey: ""
  baseUrl: "https://cloud.tenable.com"
  timeout: 30000
  maxRetries: 3

server:
  port: 8080

spring:
  application:
    name: tenable-mcp
EOL
    echo -e "${GREEN}Created application.yml. Please update it with your Tenable.io credentials.${NC}"
fi

# Build the project
echo -e "${YELLOW}Building the project...${NC}"
./gradlew clean build

if [ $? -eq 0 ]; then
    echo -e "${GREEN}Build successful!${NC}"
    
    # Print instructions
    echo -e "\n${YELLOW}To run the application:${NC}"
    echo -e "1. Update src/main/resources/application.yml with your Tenable.io credentials"
    echo -e "2. Run the application using one of these methods:"
    echo -e "   - Using Gradle: ./gradlew bootRun"
    echo -e "   - Using Java: java -jar build/libs/tenable-mcp-0.0.1-SNAPSHOT.jar"
    echo -e "   - Using Docker: docker build -t tenable-mcp . && docker run -p 8080:8080 tenable-mcp"
    
    echo -e "\n${YELLOW}API Endpoints:${NC}"
    echo -e "1. Configuration:"
    echo -e "   - GET  /api/config - Get current configuration"
    echo -e "   - POST /api/config - Update configuration"
    echo -e "2. Visualizations:"
    echo -e "   - GET  /api/v1/visualizations/report - Get comprehensive report"
    echo -e "   - GET  /api/v1/visualizations/export/vulnerabilities - Export report as CSV"
    
    echo -e "\n${YELLOW}Example API Usage:${NC}"
    echo -e "1. Update configuration:"
    echo -e "   curl -X POST http://localhost:8080/api/config -H 'Content-Type: application/json' -d '{\"accessKey\":\"your-access-key\",\"secretKey\":\"your-secret-key\"}'"
    echo -e "2. Get report:"
    echo -e "   curl http://localhost:8080/api/v1/visualizations/report"
    echo -e "3. Export CSV:"
    echo -e "   curl http://localhost:8080/api/v1/visualizations/export/vulnerabilities -o report.csv"
else
    echo -e "${RED}Build failed. Please check the error messages above.${NC}"
    exit 1
fi 