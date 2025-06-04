#!/bin/bash

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
                export SPRING_PROFILES_ACTIVE=tenable
                ./gradlew bootRun
                break
                ;;
            2)
                echo "Starting Tenable Dev environment..."
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

# Make the script executable
chmod +x start.sh

# Start the application
select_profile 