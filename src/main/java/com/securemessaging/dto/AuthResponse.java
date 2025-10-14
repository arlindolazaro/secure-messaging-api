package com.securemessaging.dto;

public class AuthResponse {
    private String token;
    private String username;
    private String email;
    private Long userId;
    private boolean hasPublicKey;
    private boolean hasDhKey;

    public AuthResponse() {
    }

    public AuthResponse(String token, String username, String email, Long userId) {
        this.token = token;
        this.username = username;
        this.email = email;
        this.userId = userId;
    }

    public AuthResponse(String token, String username, String email, Long userId, boolean hasPublicKey,
            boolean hasDhKey) {
        this.token = token;
        this.username = username;
        this.email = email;
        this.userId = userId;
        this.hasPublicKey = hasPublicKey;
        this.hasDhKey = hasDhKey;
    }

    // Getters e Setters
    public String getToken() {
        return token;
    }

    public void setToken(String token) {
        this.token = token;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public Long getUserId() {
        return userId;
    }

    public void setUserId(Long userId) {
        this.userId = userId;
    }

    public boolean isHasPublicKey() {
        return hasPublicKey;
    }

    public void setHasPublicKey(boolean hasPublicKey) {
        this.hasPublicKey = hasPublicKey;
    }

    public boolean isHasDhKey() {
        return hasDhKey;
    }

    public void setHasDhKey(boolean hasDhKey) {
        this.hasDhKey = hasDhKey;
    }
}
