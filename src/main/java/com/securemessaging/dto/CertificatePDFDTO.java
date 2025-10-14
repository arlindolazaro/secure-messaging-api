// src/main/java/com/securemessaging/dto/CertificatePDFDTO.java
package com.securemessaging.dto;

import java.time.LocalDateTime;

public class CertificatePDFDTO {
    private String subjectName;
    private String issuerName;
    private String serialNumber;
    private String publicKey;
    private LocalDateTime validFrom;
    private LocalDateTime validTo;
    private boolean revoked;
    private String status;
    private String generatedAt;

    // Construtores
    public CertificatePDFDTO() {
    }

    public CertificatePDFDTO(CertificateDTO certDTO) {
        this.subjectName = certDTO.getSubjectName();
        this.issuerName = certDTO.getIssuerName();
        this.serialNumber = certDTO.getSerialNumber();
        this.publicKey = certDTO.getPublicKey();
        this.validFrom = certDTO.getValidFrom();
        this.validTo = certDTO.getValidTo();
        this.revoked = certDTO.isRevoked();
        this.status = certDTO.isRevoked() ? "REVOGADO" : "VÁLIDO";
        this.generatedAt = LocalDateTime.now().toString();
    }

    // Getters e Setters
    public String getSubjectName() {
        return subjectName;
    }

    public void setSubjectName(String subjectName) {
        this.subjectName = subjectName;
    }

    public String getIssuerName() {
        return issuerName;
    }

    public void setIssuerName(String issuerName) {
        this.issuerName = issuerName;
    }

    public String getSerialNumber() {
        return serialNumber;
    }

    public void setSerialNumber(String serialNumber) {
        this.serialNumber = serialNumber;
    }

    public String getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(String publicKey) {
        this.publicKey = publicKey;
    }

    public LocalDateTime getValidFrom() {
        return validFrom;
    }

    public void setValidFrom(LocalDateTime validFrom) {
        this.validFrom = validFrom;
    }

    public LocalDateTime getValidTo() {
        return validTo;
    }

    public void setValidTo(LocalDateTime validTo) {
        this.validTo = validTo;
    }

    public boolean isRevoked() {
        return revoked;
    }

    public void setRevoked(boolean revoked) {
        this.revoked = revoked;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    public String getGeneratedAt() {
        return generatedAt;
    }

    public void setGeneratedAt(String generatedAt) {
        this.generatedAt = generatedAt;
    }
}