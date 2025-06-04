#!/bin/bash

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

GRADLE_VERSION="8.14.1"
GRADLE_DIST_DIR="gradle/wrapper"
GRADLE_DIST_FILE="gradle-${GRADLE_VERSION}-bin.zip"
CURRENT_DIR=$(pwd)

echo -e "${BLUE}Setting up local Gradle distribution...${NC}"

# Create gradle wrapper directory if it doesn't exist
mkdir -p "$GRADLE_DIST_DIR"

# Check if gradle distribution exists in wrapper directory
if [ -f "$GRADLE_DIST_DIR/$GRADLE_DIST_FILE" ]; then
    echo -e "${GREEN}Found Gradle distribution at $GRADLE_DIST_DIR/$GRADLE_DIST_FILE${NC}"
else
    # Check if file exists in current directory
    if [ -f "$GRADLE_DIST_FILE" ]; then
        echo -e "${YELLOW}Found Gradle distribution in current directory, moving to wrapper directory...${NC}"
        mv "$GRADLE_DIST_FILE" "$GRADLE_DIST_DIR/"
        echo -e "${GREEN}Moved Gradle distribution to $GRADLE_DIST_DIR/${NC}"
    else
        echo -e "${YELLOW}Gradle distribution not found. Please download it manually:${NC}"
        echo -e "1. Download from one of these mirrors:"
        echo -e "   - https://downloads.gradle-dn.com/distributions/$GRADLE_DIST_FILE"
        echo -e "   - https://downloads.gradle.org/distributions/$GRADLE_DIST_FILE"
        echo -e "   - https://mirrors.cloud.tencent.com/gradle/$GRADLE_DIST_FILE"
        echo -e "2. Place the downloaded file in one of these locations:"
        echo -e "   - $CURRENT_DIR/$GRADLE_DIST_DIR/$GRADLE_DIST_FILE"
        echo -e "   - $CURRENT_DIR/$GRADLE_DIST_FILE"
        echo -e "3. Run this script again after placing the file"
        exit 1
    fi
fi

# Verify the file exists and is readable
if [ ! -r "$GRADLE_DIST_DIR/$GRADLE_DIST_FILE" ]; then
    echo -e "${RED}Error: Cannot read Gradle distribution file${NC}"
    exit 1
fi

# Update gradle-wrapper.properties to use local distribution with absolute path
cat > "$GRADLE_DIST_DIR/gradle-wrapper.properties" << EOL
distributionBase=GRADLE_USER_HOME
distributionPath=wrapper/dists
distributionUrl=file\://$CURRENT_DIR/$GRADLE_DIST_DIR/$GRADLE_DIST_FILE
networkTimeout=10000
validateDistributionUrl=true
zipStoreBase=GRADLE_USER_HOME
zipStorePath=wrapper/dists
EOL

echo -e "${GREEN}Updated gradle-wrapper.properties to use local distribution${NC}"

# Make gradlew executable
if [ -f "gradlew" ]; then
    chmod +x gradlew
    echo -e "${GREEN}Made gradlew executable${NC}"
else
    echo -e "${YELLOW}Warning: gradlew not found in current directory${NC}"
fi

# Verify the setup
echo -e "\n${BLUE}Verifying setup...${NC}"
if [ -f "$GRADLE_DIST_DIR/$GRADLE_DIST_FILE" ] && [ -f "$GRADLE_DIST_DIR/gradle-wrapper.properties" ]; then
    echo -e "${GREEN}Setup verification successful!${NC}"
    echo -e "\n${YELLOW}You can now run:${NC}"
    echo -e "./gradlew bootRun"
else
    echo -e "${RED}Setup verification failed. Please check the files manually.${NC}"
    exit 1
fi 