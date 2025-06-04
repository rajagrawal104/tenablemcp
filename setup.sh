#!/bin/bash

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to handle SSL certificate issues
handle_ssl_issues() {
    echo -e "${YELLOW}SSL certificate issues detected. Attempting to resolve...${NC}"
    
    # Create a temporary directory for certificates
    CERT_DIR="$HOME/.gradle/certs"
    mkdir -p "$CERT_DIR"
    
    # Download Gradle distribution using alternative methods
    echo -e "${YELLOW}Attempting to download Gradle using alternative methods...${NC}"
    
    # Try using curl with insecure flag
    if command -v curl &> /dev/null; then
        echo -e "${YELLOW}Downloading Gradle using curl...${NC}"
        curl -k -o gradle-8.14.1-bin.zip https://services.gradle.org/distributions/gradle-8.14.1-bin.zip
        if [ $? -eq 0 ]; then
            echo -e "${GREEN}Successfully downloaded Gradle using curl.${NC}"
            return 0
        fi
    fi
    
    # Try using wget with no-check-certificate
    if command -v wget &> /dev/null; then
        echo -e "${YELLOW}Downloading Gradle using wget...${NC}"
        wget --no-check-certificate -O gradle-8.14.1-bin.zip https://services.gradle.org/distributions/gradle-8.14.1-bin.zip
        if [ $? -eq 0 ]; then
            echo -e "${GREEN}Successfully downloaded Gradle using wget.${NC}"
            return 0
        fi
    fi
    
    # If both methods fail, provide manual instructions
    echo -e "${RED}Automatic download failed. Please try the following:${NC}"
    echo -e "1. Download Gradle manually from: https://services.gradle.org/distributions/gradle-8.14.1-bin.zip"
    echo -e "2. Place the downloaded file in the project root directory"
    echo -e "3. Run the setup script again"
    return 1
}

# Function to install Java
install_java() {
    echo -e "${YELLOW}Installing Java 17...${NC}"
    case $OS in
        "macos")
            if ! command -v brew &> /dev/null; then
                echo -e "${YELLOW}Installing Homebrew...${NC}"
                /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
            fi
            brew install openjdk@17
            echo -e "${GREEN}Java 17 installed successfully.${NC}"
            ;;
        "debian")
            sudo apt-get update
            sudo apt-get install -y openjdk-17-jdk ca-certificates
            sudo update-ca-certificates
            echo -e "${GREEN}Java 17 installed successfully.${NC}"
            ;;
        "redhat")
            sudo yum install -y java-17-openjdk-devel ca-certificates
            sudo update-ca-trust
            echo -e "${GREEN}Java 17 installed successfully.${NC}"
            ;;
        *)
            echo -e "${RED}Unsupported OS for automatic Java installation.${NC}"
            echo -e "${YELLOW}Please install Java 17 manually.${NC}"
            exit 1
            ;;
    esac
}

# Function to install Docker
install_docker() {
    echo -e "${YELLOW}Installing Docker...${NC}"
    case $OS in
        "macos")
            if ! command -v brew &> /dev/null; then
                echo -e "${YELLOW}Installing Homebrew...${NC}"
                /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
            fi
            brew install --cask docker
            echo -e "${GREEN}Docker installed successfully.${NC}"
            ;;
        "debian")
            sudo apt-get update
            sudo apt-get install -y apt-transport-https ca-certificates curl software-properties-common
            curl -fsSL https://download.docker.com/linux/debian/gpg | sudo apt-key add -
            sudo add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/debian $(lsb_release -cs) stable"
            sudo apt-get update
            sudo apt-get install -y docker-ce docker-ce-cli containerd.io
            sudo usermod -aG docker $USER
            echo -e "${GREEN}Docker installed successfully.${NC}"
            ;;
        "redhat")
            sudo yum install -y yum-utils
            sudo yum-config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
            sudo yum install -y docker-ce docker-ce-cli containerd.io
            sudo systemctl start docker
            sudo systemctl enable docker
            sudo usermod -aG docker $USER
            echo -e "${GREEN}Docker installed successfully.${NC}"
            ;;
        *)
            echo -e "${RED}Unsupported OS for automatic Docker installation.${NC}"
            echo -e "${YELLOW}Please install Docker manually.${NC}"
            exit 1
            ;;
    esac
}

# Function to install Gradle
install_gradle() {
    echo -e "${YELLOW}Installing Gradle...${NC}"
    case $OS in
        "macos")
            if ! command -v brew &> /dev/null; then
                echo -e "${YELLOW}Installing Homebrew...${NC}"
                /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
            fi
            brew install gradle
            echo -e "${GREEN}Gradle installed successfully.${NC}"
            ;;
        "debian")
            sudo apt-get update
            sudo apt-get install -y gradle ca-certificates
            sudo update-ca-certificates
            echo -e "${GREEN}Gradle installed successfully.${NC}"
            ;;
        "redhat")
            sudo yum install -y gradle ca-certificates
            sudo update-ca-trust
            echo -e "${GREEN}Gradle installed successfully.${NC}"
            ;;
        *)
            echo -e "${RED}Unsupported OS for automatic Gradle installation.${NC}"
            echo -e "${YELLOW}Please install Gradle manually.${NC}"
            exit 1
            ;;
    esac
}

# Detect OS
if [[ "$OSTYPE" == "darwin"* ]]; then
    OS="macos"
elif [[ -f /etc/debian_version ]]; then
    OS="debian"
elif [[ -f /etc/redhat-release ]]; then
    OS="redhat"
else
    OS="unknown"
fi

echo -e "${GREEN}Setting up Tenable MCP Project...${NC}"
echo -e "${BLUE}Detected OS: $OS${NC}"

# Check and install Java if needed
if ! command -v java &> /dev/null; then
    echo -e "${RED}Java is not installed.${NC}"
    read -p "Would you like to install Java 17? (y/n) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        install_java
    else
        echo -e "${RED}Java is required to run this application.${NC}"
        exit 1
    fi
else
    java_version=$(java -version 2>&1 | awk -F '"' '/version/ {print $2}')
    if [[ "$java_version" < "17" ]]; then
        echo -e "${RED}Java version $java_version is not supported.${NC}"
        read -p "Would you like to install Java 17? (y/n) " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            install_java
        else
            echo -e "${RED}Java 17 or later is required to run this application.${NC}"
            exit 1
        fi
    else
        echo -e "${GREEN}Java version $java_version detected.${NC}"
    fi
fi

# Check and install Docker if needed
if ! command -v docker &> /dev/null; then
    echo -e "${YELLOW}Docker is not installed.${NC}"
    read -p "Would you like to install Docker? (y/n) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        install_docker
    else
        echo -e "${YELLOW}Docker is optional but recommended for containerized deployment.${NC}"
    fi
else
    echo -e "${GREEN}Docker detected. You can use Docker to run the application.${NC}"
fi

# Check and install Gradle if needed
if ! command -v gradle &> /dev/null; then
    echo -e "${YELLOW}Gradle is not installed.${NC}"
    read -p "Would you like to install Gradle? (y/n) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        install_gradle
    else
        echo -e "${YELLOW}Using Gradle wrapper instead.${NC}"
        # Try to download Gradle wrapper
        if ! ./gradlew --version &> /dev/null; then
            echo -e "${YELLOW}Gradle wrapper download failed. Attempting to resolve SSL issues...${NC}"
            handle_ssl_issues
        fi
    fi
else
    echo -e "${GREEN}Gradle detected.${NC}"
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