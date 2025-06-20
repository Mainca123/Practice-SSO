package com.example.authserver;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;

public class TokenService {
    private static final String SECRET = "my-secret-key";
    private static final long TOKEN_EXPIRY = 1 * 60 * 1000; // 1 giờ

    // Tạo token: username:timestamp:hash
    public static String createToken(String username) {
        long timestamp = System.currentTimeMillis();
        String tokenData = username + ":" + timestamp;
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
            // Kiểm tra hết hạn
            if (System.currentTimeMillis() - timestamp > TOKEN_EXPIRY) return false;
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
}