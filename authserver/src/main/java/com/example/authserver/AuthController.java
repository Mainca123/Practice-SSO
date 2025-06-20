package com.example.authserver;

import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;
import java.net.URLEncoder;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api")
@CrossOrigin(origins = {"http://localhost:8081", "http://localhost:8082"})
@Slf4j
public class AuthController {

    private static final Map<String, String> users = new HashMap<>();
    private static final Map<String, UserSession> tokens = new HashMap<>();

    static class UserSession {
        String username;
        long timestamp;
        String refreshToken;
        long refreshTokenTimestamp;

        UserSession(String username, long timestamp, String refreshToken, long refreshTokenTimestamp) {
            this.username = username;
            this.timestamp = timestamp;
            this.refreshToken = refreshToken;
            this.refreshTokenTimestamp = refreshTokenTimestamp;
        }
    }

    static {
        users.put("user1", "password1");
        users.put("user2", "password2");
        users.put("user3", "password3");
        users.put("admin", "admin123");
    }

    @PostMapping("/login")
    public ResponseEntity<Map<String, String>> login(
            @RequestBody Map<String, String> credentials,
            @RequestParam String redirect_uri) {

        String username = credentials.get("username");
        String password = credentials.get("password");

        Map<String, String> response = new HashMap<>();

        if (username == null || password == null || !users.containsKey(username.trim())
                || !users.get(username.trim()).equals(password.trim())) {
            response.put("error", "Invalid credentials");
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(response);
        }

        username = username.trim(); // chuẩn hóa
        long timestamp = System.currentTimeMillis();
        String token = TokenService.createToken(username);
        long refreshTokenTimestamp = System.currentTimeMillis();
        String refreshToken = TokenService.createRefreshToken(username);
        tokens.put(token, new UserSession(username, timestamp, refreshToken, refreshTokenTimestamp));

        // ✅ Kiểm tra lại token để đảm bảo hợp lệ
        if (!TokenService.verifyToken(token, username, timestamp) ||
                !TokenService.verifyRefreshToken(refreshToken, username, refreshTokenTimestamp)) {
            response.put("error", "Failed to verify generated token");
            tokens.remove(token);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(response);
        }
        response.put("refreshToken", refreshToken);
        response.put("token", token);
        response.put("username", username);
        response.put("redirect_uri", redirect_uri);
        log.info("login {}", CommonUtil.beanToString(response));
        return ResponseEntity.ok(response);
    }

    @PostMapping("/verify-token")
    public ResponseEntity<Map<String, Object>> verifyToken(@RequestBody Map<String, String> request) {
        log.info("verifyToken {}", CommonUtil.beanToString(request));
        Map<String, Object> response = new HashMap<>();
        try {
            String token = request.get("token");

            if (token == null || token.isEmpty()) {
                response.put("valid", false);
                response.put("error", "Missing token");
                return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(response);
            }

            UserSession session = tokens.get(token);
            if (session == null) {
                response.put("valid", false);
                response.put("error", "Token not found");
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(response);
            }

            if (TokenService.verifyToken(token, session.username, session.timestamp)) {
                response.put("valid", true);
                response.put("username", session.username);
                return ResponseEntity.ok(response);
            } else {
//                tokens.remove(token);
                response.put("valid", false);
                response.put("error", "Invalid or expired token");
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(response);
            }
        } catch (Exception e) {
            e.printStackTrace();
            response.put("valid", false);
            response.put("error", "Server error: " + e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(response);
        }
    }

    @PostMapping("/logout")
    public ResponseEntity<Map<String, String>> logout(@RequestBody Map<String, String> request) {
        String token = request.get("token");
        Map<String, String> response = new HashMap<>();

        if (token != null && tokens.containsKey(token)) {
            tokens.remove(token);
        }

        response.put("message", "Logged out successfully");
        log.info("logout {}", CommonUtil.beanToString(response));
        return ResponseEntity.ok(response);
    }

    @PostMapping("/sso-login")
    public void loginWithRedirect(@RequestParam String username,
                                  @RequestParam String password,
                                  @RequestParam String redirect_uri,
                                  HttpServletResponse response) throws IOException {
        if (username == null || password == null || !users.containsKey(username.trim())
                || !users.get(username.trim()).equals(password.trim())) {
            response.sendRedirect("/login?error=1");
            return;
        }

        username = username.trim();
        long timestamp = System.currentTimeMillis();
        String token = TokenService.createToken(username);
        long refreshTokenTimestamp = System.currentTimeMillis();
        String refreshToken = TokenService.createToken(username);
        tokens.put(token, new UserSession(username, timestamp, refreshToken, refreshTokenTimestamp));

        // ✅ Kiểm tra lại token vừa sinh
        if (!TokenService.verifyToken(token, username, timestamp)) {
            response.sendRedirect("/login?error=2");
            return;
        }

        String redirectWithToken = redirect_uri + "?token=" + URLEncoder.encode(token, "UTF-8") + "&refreshToken=" + URLEncoder.encode(refreshToken, "UTF-8");
        response.sendRedirect(redirectWithToken);
    }


    @PostMapping("/refresh-token")
    public ResponseEntity<Map<String, String>> refreshToken(@RequestBody Map<String, String> request) {
        log.info("refreshToken {}", CommonUtil.beanToString(request));
        String refreshToken = request.get("refreshToken");
        Map<String, String> response = new HashMap<>();

        if (refreshToken == null || refreshToken.isEmpty()) {
            response.put("error", "Missing refresh token");
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(response);
        }

        // Tìm session theo refreshToken
        UserSession session = null;
        for (UserSession us : tokens.values()) {
            if (us.refreshToken.equals(refreshToken)) {
                session = us;
                break;
            }
        }

        if (session == null) {
            response.put("error", "Invalid refresh token");
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(response);
        }

        // Kiểm tra refreshToken hợp lệ
        if (!TokenService.verifyRefreshToken(refreshToken, session.username, session.refreshTokenTimestamp)) {
            response.put("error", "Refresh token expired or invalid");
            tokens.values().removeIf(us -> us.refreshToken.equals(refreshToken));
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(response);
        }

        // Sinh access token mới
        long timestamp = System.currentTimeMillis();
        String newToken = TokenService.createToken(session.username);
        tokens.put(newToken, new UserSession(session.username, timestamp, refreshToken, session.refreshTokenTimestamp));

        response.put("token", newToken);
        response.put("username", session.username);
        log.info("refreshToken {}", CommonUtil.beanToString(response));
        return ResponseEntity.ok(response);
    }
}
