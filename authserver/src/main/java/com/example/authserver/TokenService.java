package com.example.authserver;

import lombok.extern.slf4j.Slf4j;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;

@Slf4j
public class TokenService {
    private static final String SECRET = "my-secret-key";
    private static final long TOKEN_EXPIRY = 1 * 60 * 1000; // 1 phut
    //    private static final long REFRESH_TOKEN_EXPIRY = 7 * 24 * 60 * 60 * 1000; // 7 ngày
    private static final long REFRESH_TOKEN_EXPIRY = 10 * 60 * 1000; // 10 phút

    // Tạo token: username:timestamp:hash
    public static String createToken(String username) {
        long timestamp = System.currentTimeMillis();
        String tokenData = username + ":" + timestamp;
        String tokenHash = hash(tokenData + SECRET);
        return Base64.getUrlEncoder().encodeToString((tokenData + ":" + tokenHash).getBytes());
    }

    public static String createRefreshToken(String username) {
        long timestamp = System.currentTimeMillis();
        String tokenData = username + ":refresh:" + timestamp;
        String tokenHash = hash(tokenData + SECRET);
        return Base64.getUrlEncoder().encodeToString((tokenData + ":" + tokenHash).getBytes());
    }

    // Xác minh token
    public static boolean verifyToken(String token, String storedUsername, long storedTimestamp) {
        try {
            String[] tokenParts = new String(Base64.getUrlDecoder().decode(token)).split(":");
            if (tokenParts.length != 3) return false;
            String username = tokenParts[0];
            long timestamp = Long.parseLong(tokenParts[1]);
            String tokenHash = tokenParts[2];

            // Kiểm tra username và timestamp
            if (!username.equals(storedUsername) || timestamp != storedTimestamp) return false;
            long now = System.currentTimeMillis();
            long millisLeft = TOKEN_EXPIRY - (now - timestamp);
            long minutesLeft = millisLeft / (60 * 1000);
            long secondsLeft = (millisLeft % (60 * 1000)) / 1000;
            log.info("Token còn lại: {} - {} phút {} giây ({} ms)",username, minutesLeft, secondsLeft, millisLeft);
            // Kiểm tra hết hạn
            if (System.currentTimeMillis() - timestamp > TOKEN_EXPIRY) {
                return false;
            }
            // Kiểm tra hash
            String tokenData = username + ":" + timestamp;
            return tokenHash.equals(hash(tokenData + SECRET));
        } catch (Exception e) {
            return false;
        }
    }

    private static String hash(String input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(input.getBytes(StandardCharsets.UTF_8));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
        } catch (Exception e) {
            throw new RuntimeException("Failed to hash", e);
        }
    }

    public static boolean verifyRefreshToken(String refreshToken, String storedUsername, long storedTimestamp) {
        try {
            String[] tokenParts = new String(Base64.getUrlDecoder().decode(refreshToken)).split(":");
            // Format: username:refresh:timestamp:hash
            if (tokenParts.length != 4) return false;
            String username = tokenParts[0];
            String refreshFlag = tokenParts[1];
            long timestamp = Long.parseLong(tokenParts[2]);
            String tokenHash = tokenParts[3];

            // Kiểm tra username, refreshFlag và timestamp
            if (!username.equals(storedUsername) || !"refresh".equals(refreshFlag) || timestamp != storedTimestamp)
                return false;
            long now = System.currentTimeMillis();
            long millisLeft = REFRESH_TOKEN_EXPIRY - (now - timestamp);
            long minutesLeft = millisLeft / (60 * 1000);
            long secondsLeft = (millisLeft % (60 * 1000)) / 1000;
            log.info("RefreshToken còn lại: {} - {} phút {} giây ({} ms)",username, minutesLeft, secondsLeft, millisLeft);
            // Kiểm tra hết hạn
            if (System.currentTimeMillis() - timestamp > REFRESH_TOKEN_EXPIRY) {
                return false;
            }
            // Kiểm tra hash
            String tokenData = username + ":refresh:" + timestamp;
            return tokenHash.equals(hash(tokenData + SECRET));
        } catch (Exception e) {
            return false;
        }
    }
}