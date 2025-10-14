// src/main/java/com/securemessaging/dto/DiffieHellmanDTO.java
package com.securemessaging.dto;

import java.math.BigInteger;

public class DiffieHellmanDTO {
    private BigInteger prime;
    private BigInteger generator;
    private BigInteger privateKey;
    private BigInteger publicKey;
    private BigInteger sharedSecret;

    // Construtores 
    public DiffieHellmanDTO() {
    }

    public DiffieHellmanDTO(BigInteger prime, BigInteger generator) {
        this.prime = prime;
        this.generator = generator;
    }

    // Getters e Setters
    public BigInteger getPrime() {
        return prime;
    }

    public void setPrime(BigInteger prime) {
        this.prime = prime;
    }

    public BigInteger getGenerator() {
        return generator;
    }

    public void setGenerator(BigInteger generator) {
        this.generator = generator;
    }

    public BigInteger getPrivateKey() {
        return privateKey;
    }

    public void setPrivateKey(BigInteger privateKey) {
        this.privateKey = privateKey;
    }

    public BigInteger getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(BigInteger publicKey) {
        this.publicKey = publicKey;
    }

    public BigInteger getSharedSecret() {
        return sharedSecret;
    }

    public void setSharedSecret(BigInteger sharedSecret) {
        this.sharedSecret = sharedSecret;
    }
}