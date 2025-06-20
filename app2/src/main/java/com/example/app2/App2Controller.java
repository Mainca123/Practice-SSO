package com.example.app2;

import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;

import java.util.HashMap;
import java.util.Map;

@RestController
@CrossOrigin(origins = "http://localhost:8082") // Cho phép frontend của App2
@Slf4j
public class App2Controller {
    private final RestTemplate restTemplate = new RestTemplate();

    @GetMapping("/protected")
    public ResponseEntity<Map<String, String>> protectedResource(
            @RequestHeader(value = "Authorization", required = false) String authorization) {

        Map<String, String> result = new HashMap<>();

        if (authorization == null || authorization.isEmpty()) {
            result.put("error", "No token provided");
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(result);
        }

        try {
            // Gửi token đến Auth Server để xác minh
            Map<String, String> request = new HashMap<>();
            request.put("token", authorization);
            log.info("request {}",CommonUtil.beanToString(request));
            ResponseEntity<Map> verifyResponse = restTemplate.postForEntity(
                    "http://localhost:8080/api/verify-token", request, Map.class);

            if (verifyResponse.getStatusCode() != HttpStatus.OK || verifyResponse.getBody() == null) {
                result.put("error", "Invalid response from Auth Server");
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(result);
            }

            Map<String, Object> body = verifyResponse.getBody();
            Boolean valid = (Boolean) body.get("valid");

            if (Boolean.TRUE.equals(valid)) {
                String username = (String) body.get("username");
                result.put("message", "App2: Bạn đã đăng nhập với tên là " + username);
                return ResponseEntity.ok(result);
            } else {
                String errorMsg = (String) body.getOrDefault("error", "Invalid token");
                result.put("error", errorMsg);
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(result);
            }
        } catch (Exception e) {
            result.put("error", "Auth Server unreachable: " + e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(result);
        }
    }

    @PostMapping("/logout")
    public ResponseEntity<Map<String, String>> logout(
            @RequestHeader(value = "Authorization", required = false) String authorization) {

        Map<String, String> result = new HashMap<>();

        if (authorization == null || authorization.isEmpty()) {
            result.put("error", "No token provided");
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(result);
        }

        try {
            Map<String, String> request = new HashMap<>();
            request.put("token", authorization);

            // Gửi yêu cầu logout tới Auth Server
            restTemplate.postForEntity("http://localhost:8080/api/logout", request, Map.class);
        } catch (Exception e) {
            // Không cần xử lý lỗi logout ở đây
        }

        result.put("message", "App2: Logged out successfully");
        return ResponseEntity.ok(result);
    }
}
