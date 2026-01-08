FROM eclipse-temurin:21.0.9_10-jre-ubi9-minimal
WORKDIR /app
COPY target/*.jar app.jar
ENTRYPOINT ["java", "-jar", "app.jar"]