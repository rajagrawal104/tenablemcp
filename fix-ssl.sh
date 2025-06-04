#!/bin/bash

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to detect OS
detect_os() {
    if [[ "$OSTYPE" == "darwin"* ]]; then
        OS="macos"
    elif [[ -f /etc/debian_version ]]; then
        OS="debian"
    elif [[ -f /etc/redhat-release ]]; then
        OS="redhat"
    else
        OS="unknown"
    fi
    echo -e "${BLUE}Detected OS: $OS${NC}"
}

# Function to install CA certificates
install_ca_certificates() {
    echo -e "${YELLOW}Installing CA certificates...${NC}"
    case $OS in
        "macos")
            if ! command -v brew &> /dev/null; then
                echo -e "${YELLOW}Installing Homebrew...${NC}"
                /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
            fi
            brew install ca-certificates
            ;;
        "debian")
            sudo apt-get update
            sudo apt-get install -y ca-certificates
            sudo update-ca-certificates
            ;;
        "redhat")
            sudo yum install -y ca-certificates
            sudo update-ca-trust
            ;;
        *)
            echo -e "${RED}Unsupported OS for automatic CA certificate installation.${NC}"
            return 1
            ;;
    esac
    echo -e "${GREEN}CA certificates installed successfully.${NC}"
}

# Function to download Gradle distribution
download_gradle() {
    local version="8.14.1"
    local url="https://services.gradle.org/distributions/gradle-${version}-bin.zip"
    local output="gradle-${version}-bin.zip"
    
    echo -e "${YELLOW}Attempting to download Gradle ${version}...${NC}"
    
    # Try different methods to download
    if command -v curl &> /dev/null; then
        echo -e "${YELLOW}Attempting download with curl...${NC}"
        curl -k -L -o "$output" "$url"
        if [ $? -eq 0 ]; then
            echo -e "${GREEN}Successfully downloaded Gradle using curl.${NC}"
            return 0
        fi
    fi
    
    if command -v wget &> /dev/null; then
        echo -e "${YELLOW}Attempting download with wget...${NC}"
        wget --no-check-certificate -O "$output" "$url"
        if [ $? -eq 0 ]; then
            echo -e "${GREEN}Successfully downloaded Gradle using wget.${NC}"
            return 0
        fi
    fi
    
    # If both methods fail, try downloading from mirror
    echo -e "${YELLOW}Attempting download from mirror...${NC}"
    local mirror_url="https://downloads.gradle-dn.com/distributions/gradle-${version}-bin.zip"
    if command -v curl &> /dev/null; then
        curl -k -L -o "$output" "$mirror_url"
        if [ $? -eq 0 ]; then
            echo -e "${GREEN}Successfully downloaded Gradle from mirror using curl.${NC}"
            return 0
        fi
    fi
    
    if command -v wget &> /dev/null; then
        wget --no-check-certificate -O "$output" "$mirror_url"
        if [ $? -eq 0 ]; then
            echo -e "${GREEN}Successfully downloaded Gradle from mirror using wget.${NC}"
            return 0
        fi
    fi
    
    echo -e "${RED}All download attempts failed.${NC}"
    return 1
}

# Function to configure Java security
configure_java_security() {
    echo -e "${YELLOW}Configuring Java security settings...${NC}"
    
    # Find Java home
    if [ -n "$JAVA_HOME" ]; then
        JAVA_SECURITY_DIR="$JAVA_HOME/lib/security"
    else
        # Try to find Java home
        if command -v java &> /dev/null; then
            JAVA_HOME=$(java -XshowSettings:properties -version 2>&1 | grep 'java.home' | awk '{print $3}')
            JAVA_SECURITY_DIR="$JAVA_HOME/lib/security"
        else
            echo -e "${RED}Java not found. Please set JAVA_HOME environment variable.${NC}"
            return 1
        fi
    fi
    
    # Backup original security settings
    if [ -f "$JAVA_SECURITY_DIR/java.security" ]; then
        cp "$JAVA_SECURITY_DIR/java.security" "$JAVA_SECURITY_DIR/java.security.backup"
        echo -e "${GREEN}Backed up original security settings.${NC}"
    fi
    
    # Update security settings
    echo -e "${YELLOW}Updating Java security settings...${NC}"
    sed -i.bak 's/^security.provider.1=.*/security.provider.1=com.sun.security.provider.Sun/g' "$JAVA_SECURITY_DIR/java.security"
    sed -i.bak 's/^security.provider.2=.*/security.provider.2=sun.security.provider.Sun/g' "$JAVA_SECURITY_DIR/java.security"
    
    echo -e "${GREEN}Java security settings updated.${NC}"
}

# Function to create gradle.properties with SSL settings
configure_gradle_ssl() {
    echo -e "${YELLOW}Configuring Gradle SSL settings...${NC}"
    
    GRADLE_USER_HOME="$HOME/.gradle"
    mkdir -p "$GRADLE_USER_HOME"
    
    cat > "$GRADLE_USER_HOME/gradle.properties" << EOL
systemProp.javax.net.ssl.trustStore=$JAVA_HOME/lib/security/cacerts
systemProp.javax.net.ssl.trustStorePassword=changeit
systemProp.javax.net.ssl.trustStoreType=JKS
systemProp.https.protocols=TLSv1.2,TLSv1.3
EOL
    
    echo -e "${GREEN}Gradle SSL settings configured.${NC}"
}

# Main execution
echo -e "${GREEN}Starting SSL configuration...${NC}"

# Detect OS
detect_os

# Install CA certificates
install_ca_certificates

# Configure Java security
configure_java_security

# Configure Gradle SSL settings
configure_gradle_ssl

# Download Gradle
download_gradle

echo -e "\n${GREEN}SSL configuration completed.${NC}"
echo -e "${YELLOW}If you still experience SSL issues, try the following:${NC}"
echo -e "1. Run the application with SSL debugging enabled:"
echo -e "   ./gradlew bootRun -Djavax.net.debug=ssl:handshake"
echo -e "2. Check your system's date and time are correct"
echo -e "3. Ensure your system's CA certificates are up to date"
echo -e "4. If using a proxy, configure it in gradle.properties:"
echo -e "   systemProp.http.proxyHost=proxy.company.com"
echo -e "   systemProp.http.proxyPort=8080"
echo -e "   systemProp.https.proxyHost=proxy.company.com"
echo -e "   systemProp.https.proxyPort=8080" 