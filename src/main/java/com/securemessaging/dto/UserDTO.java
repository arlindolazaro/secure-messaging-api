package com.securemessaging.dto;

import java.time.LocalDateTime;

public class UserDTO {
    private Long id;
    private String username;
    private String email;
    private String publicKey;
    private String dhPublicKey;
    private String certificate;
    private boolean enabled;
    private LocalDateTime createdAt;
    private LocalDateTime lastLogin;

    // Contadores adicionais
    private int certificateCount;
    private int keyPairCount;
    private int sentMessageCount;
    private int receivedMessageCount;

    public UserDTO() {
    }

    public UserDTO(Long id, String username, String email, String publicKey) {
        this.id = id;
        this.username = username;
        this.email = email;
        this.publicKey = publicKey;
    }

    // Getters e Setters
    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
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

    public String getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(String publicKey) {
        this.publicKey = publicKey;
    }

    public String getDhPublicKey() {
        return dhPublicKey;
    }

    public void setDhPublicKey(String dhPublicKey) {
        this.dhPublicKey = dhPublicKey;
    }

    public String getCertificate() {
        return certificate;
    }

    public void setCertificate(String certificate) {
        this.certificate = certificate;
    }

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public LocalDateTime getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(LocalDateTime createdAt) {
        this.createdAt = createdAt;
    }

    public LocalDateTime getLastLogin() {
        return lastLogin;
    }

    public void setLastLogin(LocalDateTime lastLogin) {
        this.lastLogin = lastLogin;
    }

    public int getCertificateCount() {
        return certificateCount;
    }

    public void setCertificateCount(int certificateCount) {
        this.certificateCount = certificateCount;
    }

    public int getKeyPairCount() {
        return keyPairCount;
    }

    public void setKeyPairCount(int keyPairCount) {
        this.keyPairCount = keyPairCount;
    }

    public int getSentMessageCount() {
        return sentMessageCount;
    }

    public void setSentMessageCount(int sentMessageCount) {
        this.sentMessageCount = sentMessageCount;
    }

    public int getReceivedMessageCount() {
        return receivedMessageCount;
    }

    public void setReceivedMessageCount(int receivedMessageCount) {
        this.receivedMessageCount = receivedMessageCount;
    }
}
