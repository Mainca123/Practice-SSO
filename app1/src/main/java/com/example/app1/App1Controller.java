package com.example.app1;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;

import java.util.HashMap;
import java.util.Map;

@RestController
@CrossOrigin(origins = "http://localhost:8081") // Cho phép frontend App1 truy cập
public class App1Controller {

    private final RestTemplate restTemplate = new RestTemplate();

    @GetMapping("/protected")
    public ResponseEntity<Map<String, String>> protectedResource(
            @RequestHeader(value = "Authorization", required = false) String token) {

        Map<String, String> result = new HashMap<>();

        if (token == null || token.trim().isEmpty()) {
            result.put("error", "Token không được để trống");
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(result);
        }

        try {
            Map<String, String> request = new HashMap<>();
            request.put("token", token);

            ResponseEntity<Map> response = restTemplate.postForEntity(
                    "http://auth-server:8080/api/verify-token", request, Map.class);

            if (response.getStatusCode() != HttpStatus.OK || response.getBody() == null) {
                result.put("error", "Phản hồi không hợp lệ từ Auth Server");
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(result);
            }

            Map body = response.getBody();
            Object valid = body.get("valid");

            if (Boolean.TRUE.equals(valid)) {
                String username = (String) body.get("username");
                result.put("message", "App1: Bạn đã đăng nhập với tên là " + username);
                return ResponseEntity.ok(result);
            } else {
                result.put("error", (String) body.getOrDefault("error", "Token không hợp lệ"));
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(result);
            }

        } catch (Exception e) {
            result.put("error", "Lỗi xác minh token: " + e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(result);
        }
    }

    @PostMapping("/logout")
    public ResponseEntity<Map<String, String>> logout(
            @RequestHeader(value = "Authorization", required = false) String token) {

        Map<String, String> result = new HashMap<>();

        if (token == null || token.trim().isEmpty()) {
            result.put("error", "Token không được để trống");
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(result);
        }

        try {
            Map<String, String> request = new HashMap<>();
            request.put("token", token);

            // Gọi logout đến Auth Server, không cần kiểm tra response
            restTemplate.postForEntity("http://auth-server:8080/api/logout", request, Map.class);

            result.put("message", "App1: Đăng xuất thành công");
            return ResponseEntity.ok(result);
        } catch (Exception e) {
            result.put("error", "Lỗi khi đăng xuất: " + e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(result);
        }
    }
}
