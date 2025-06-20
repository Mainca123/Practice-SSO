# 1. Dùng base image Java 17
FROM eclipse-temurin:17-jdk

# 2. Tạo thư mục làm việc trong container
WORKDIR /app

# 3. Copy file JAR từ thư mục target
COPY target/*.jar app.jar

# 4. Mở cổng 8080
EXPOSE 8080

# 5. Chạy ứng dụng
ENTRYPOINT ["java", "-jar", "app.jar"]
