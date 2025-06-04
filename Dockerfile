# Use the official Gradle image as a builder
FROM gradle:7.6.1-jdk17 AS builder

# Set the working directory
WORKDIR /app

# Copy the project files
COPY . .

# Build the application
RUN gradle build --no-daemon

# Use the official OpenJDK image as the base image
FROM openjdk:17-slim

# Set the working directory
WORKDIR /app

# Copy the built JAR file from the builder stage
COPY --from=builder /app/build/libs/*.jar app.jar

# Expose the application port
EXPOSE 8080

# Set environment variables
ENV JAVA_OPTS="-Xmx512m -Xms256m"

# Run the application
ENTRYPOINT ["sh", "-c", "java $JAVA_OPTS -jar app.jar"] 