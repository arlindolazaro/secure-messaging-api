package com.securemessaging.model;

import jakarta.persistence.*;
import java.time.LocalDateTime;

@Entity
@Table(name = "key_pairs")
public class KeyPair {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    @Column(columnDefinition = "TEXT")
    private String publicKey;

    @Column(columnDefinition = "TEXT")
    private String privateKey;

    private String algorithm;
    private int keySize; 

    @Enumerated(EnumType.STRING)
    private KeyType keyType; 

    private LocalDateTime createdAt;
    private LocalDateTime expiresAt;
    private boolean active = true;

    public KeyPair() {
        this.createdAt = LocalDateTime.now();
    }

    public KeyPair(User user, String publicKey, String privateKey, String algorithm, int keySize, KeyType keyType) {
        this();
        this.user = user;
        this.publicKey = publicKey;
        this.privateKey = privateKey;
        this.algorithm = algorithm;
        this.keySize = keySize;
        this.keyType = keyType;
        // Expira em 1 ano por padrão
        this.expiresAt = LocalDateTime.now().plusYears(1);
    }

    // Enum para tipo de chave
    public enum KeyType {
        ENCRYPTION, SIGNATURE, KEY_EXCHANGE
    }

    // Getters e Setters
    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public User getUser() {
        return user;
    }

    public void setUser(User user) {
        this.user = user;
    }

    public String getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(String publicKey) {
        this.publicKey = publicKey;
    }

    public String getPrivateKey() {
        return privateKey;
    }

    public void setPrivateKey(String privateKey) {
        this.privateKey = privateKey;
    }

    public String getAlgorithm() {
        return algorithm;
    }

    public void setAlgorithm(String algorithm) {
        this.algorithm = algorithm;
    }

    public int getKeySize() {
        return keySize;
    }

    public void setKeySize(int keySize) {
        this.keySize = keySize;
    }

    public KeyType getKeyType() {
        return keyType;
    }

    public void setKeyType(KeyType keyType) {
        this.keyType = keyType;
    }

    public LocalDateTime getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(LocalDateTime createdAt) {
        this.createdAt = createdAt;
    }

    public LocalDateTime getExpiresAt() {
        return expiresAt;
    }

    public void setExpiresAt(LocalDateTime expiresAt) {
        this.expiresAt = expiresAt;
    }

    public boolean isActive() {
        return active;
    }

    public void setActive(boolean active) {
        this.active = active;
    }
}