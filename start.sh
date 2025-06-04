#!/bin/bash

# Function to check if API keys are set
check_api_keys() {
    local profile=$1
    local access_key_var="TENABLE_ACCESS_KEY"
    local secret_key_var="TENABLE_SECRET_KEY"
    local url_var="TENABLE_API_URL"
    
    if [ "$profile" = "tenabledev" ]; then
        access_key_var="TENABLE_DEV_ACCESS_KEY"
        secret_key_var="TENABLE_DEV_SECRET_KEY"
    fi

    # Check if API URL is set
    if [ -z "${!url_var}" ]; then
        echo "API URL not found for $profile environment."
        read -p "Enter API URL (default: https://cloud.tenable.com): " api_url
        api_url=${api_url:-https://cloud.tenable.com}
        export "$url_var"="$api_url"
        echo "$url_var=$api_url" >> .env
    fi

    # Check if keys are set
    if [ -z "${!access_key_var}" ] || [ -z "${!secret_key_var}" ]; then
        echo "API keys not found for $profile environment."
        echo "Please enter your API keys:"
        
        # Prompt for Access Key
        read -p "Enter Access Key: " access_key
        export "$access_key_var"="$access_key"
        
        # Prompt for Secret Key
        read -p "Enter Secret Key: " secret_key
        export "$secret_key_var"="$secret_key"
        
        # Save to .env file
        echo "$access_key_var=$access_key" >> .env
        echo "$secret_key_var=$secret_key" >> .env
        
        echo "API keys have been saved to .env file"
    fi
}

# Function to display menu
show_menu() {
    echo "Select environment to run:"
    echo "1) Tenable Production"
    echo "2) Tenable Dev"
    echo "q) Quit"
    echo
    echo -n "Enter your choice [1-2 or q]: "
}

# Function to handle profile selection
select_profile() {
    while true; do
        show_menu
        read -r choice
        case $choice in
            1)
                echo "Starting Tenable Production environment..."
                check_api_keys "tenable"
                export SPRING_PROFILES_ACTIVE=tenable
                ./gradlew bootRun
                break
                ;;
            2)
                echo "Starting Tenable Dev environment..."
                check_api_keys "tenabledev"
                export SPRING_PROFILES_ACTIVE=tenabledev
                ./gradlew bootRun
                break
                ;;
            q|Q)
                echo "Exiting..."
                exit 0
                ;;
            *)
                echo "Invalid option. Please try again."
                ;;
        esac
    done
}

# Load existing environment variables from .env file if it exists
if [ -f .env ]; then
    echo "Loading existing environment variables from .env file..."
    export $(cat .env | xargs)
fi

# Make the script executable
chmod +x start.sh

# Start the application
select_profile 