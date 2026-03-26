# Base image
FROM eclipse-temurin:17-jdk-alpine AS build

WORKDIR /app

# Copy Maven project files and download dependencies
COPY pom.xml .
COPY src ./src

# Build jar
RUN ./mvnw -B clean package -DskipTests

# Runtime image
FROM eclipse-temurin:17-jdk-alpine
WORKDIR /app

# Copy application jar
COPY --from=build /app/target/secure-llm-gateway.jar ./secure-llm-gateway.jar

EXPOSE 8080

ENTRYPOINT ["java", "-jar", "secure-llm-gateway.jar"]
