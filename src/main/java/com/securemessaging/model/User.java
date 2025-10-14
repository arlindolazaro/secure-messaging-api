package com.securemessaging.model;

import jakarta.persistence.*;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

@Entity
@Table(name = "users")
public class User {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(unique = true, nullable = false)
    private String username;

    @Column(unique = true, nullable = false)
    private String email;

    @Column(nullable = false)
    private String password;

    // Chaves RSA
    @Column(columnDefinition = "TEXT")
    private String publicKey;

    @Column(columnDefinition = "TEXT")
    private String privateKey;

    // Parâmetros Diffie-Hellman
    @Column(columnDefinition = "TEXT")
    private String dhPublicKey;

    @Column(columnDefinition = "TEXT")
    private String dhPrivateKey;

    @Column(columnDefinition = "TEXT")
    private String dhPrimeModulus; // p

    @Column(columnDefinition = "TEXT")
    private String dhGenerator; // g

    @Column(columnDefinition = "TEXT")
    private String certificate;

    private boolean enabled = true;
    private LocalDateTime createdAt;
    private LocalDateTime lastLogin;

    // Relações
    @OneToMany(mappedBy = "user", cascade = CascadeType.ALL, fetch = FetchType.LAZY)
    private List<Certificate> certificates = new ArrayList<>();

    @OneToMany(mappedBy = "sender", cascade = CascadeType.ALL, fetch = FetchType.LAZY)
    private List<Message> sentMessages = new ArrayList<>();

    @OneToMany(mappedBy = "receiver", cascade = CascadeType.ALL, fetch = FetchType.LAZY)
    private List<Message> receivedMessages = new ArrayList<>();

    @OneToMany(mappedBy = "user", cascade = CascadeType.ALL, fetch = FetchType.LAZY)
    private List<KeyPair> keyPairs = new ArrayList<>();

    public User() {
        this.createdAt = LocalDateTime.now();
    }

    public User(String username, String email, String password) {
        this();
        this.username = username;
        this.email = email;
        this.password = password;
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

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
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

    public String getDhPublicKey() {
        return dhPublicKey;
    }

    public void setDhPublicKey(String dhPublicKey) {
        this.dhPublicKey = dhPublicKey;
    }

    public String getDhPrivateKey() {
        return dhPrivateKey;
    }

    public void setDhPrivateKey(String dhPrivateKey) {
        this.dhPrivateKey = dhPrivateKey;
    }

    public String getDhPrimeModulus() {
        return dhPrimeModulus;
    }

    public void setDhPrimeModulus(String dhPrimeModulus) {
        this.dhPrimeModulus = dhPrimeModulus;
    }

    public String getDhGenerator() {
        return dhGenerator;
    }

    public void setDhGenerator(String dhGenerator) {
        this.dhGenerator = dhGenerator;
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

    public List<Certificate> getCertificates() {
        return certificates;
    }

    public void setCertificates(List<Certificate> certificates) {
        this.certificates = certificates;
    }

    public List<Message> getSentMessages() {
        return sentMessages;
    }

    public void setSentMessages(List<Message> sentMessages) {
        this.sentMessages = sentMessages;
    }

    public List<Message> getReceivedMessages() {
        return receivedMessages;
    }

    public void setReceivedMessages(List<Message> receivedMessages) {
        this.receivedMessages = receivedMessages;
    }

    public List<KeyPair> getKeyPairs() {
        return keyPairs;
    }

    public void setKeyPairs(List<KeyPair> keyPairs) {
        this.keyPairs = keyPairs;
    }
}