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

echo -e "${BLUE}Setting up local Gradle distribution...${NC}"

# Create gradle wrapper directory if it doesn't exist
mkdir -p "$GRADLE_DIST_DIR"

# Check if gradle distribution already exists
if [ -f "$GRADLE_DIST_DIR/$GRADLE_DIST_FILE" ]; then
    echo -e "${GREEN}Gradle distribution already exists at $GRADLE_DIST_DIR/$GRADLE_DIST_FILE${NC}"
else
    echo -e "${YELLOW}Please download Gradle distribution manually:${NC}"
    echo -e "1. Download from one of these mirrors:"
    echo -e "   - https://downloads.gradle-dn.com/distributions/$GRADLE_DIST_FILE"
    echo -e "   - https://downloads.gradle.org/distributions/$GRADLE_DIST_FILE"
    echo -e "   - https://mirrors.cloud.tencent.com/gradle/$GRADLE_DIST_FILE"
    echo -e "2. Place the downloaded file at: $GRADLE_DIST_DIR/$GRADLE_DIST_FILE"
    echo -e "3. Run this script again after placing the file"
    exit 1
fi

# Update gradle-wrapper.properties to use local distribution
cat > "$GRADLE_DIST_DIR/gradle-wrapper.properties" << EOL
distributionBase=GRADLE_USER_HOME
distributionPath=wrapper/dists
distributionUrl=file\:///\${projectDir}/gradle/wrapper/${GRADLE_DIST_FILE}
networkTimeout=10000
validateDistributionUrl=true
zipStoreBase=GRADLE_USER_HOME
zipStorePath=wrapper/dists
EOL

echo -e "${GREEN}Updated gradle-wrapper.properties to use local distribution${NC}"

# Make gradlew executable
chmod +x gradlew

echo -e "\n${GREEN}Local Gradle setup completed!${NC}"
echo -e "${YELLOW}You can now run:${NC}"
echo -e "./gradlew bootRun" 