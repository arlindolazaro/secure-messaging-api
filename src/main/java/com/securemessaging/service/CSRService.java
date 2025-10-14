// src/main/java/com/securemessaging/service/CSRService.java
package com.securemessaging.service;

import com.securemessaging.dto.CSRDTO;
import com.securemessaging.dto.CSRRequest;
import com.securemessaging.model.Certificate;
import com.securemessaging.model.CertificateSigningRequest;
import com.securemessaging.model.User;
import com.securemessaging.repository.CSRRepository;
import com.securemessaging.repository.CertificateRepository;
import com.securemessaging.repository.UserRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.PublicKey;
import java.time.LocalDateTime;
import java.util.Base64;
import java.util.List;
import java.util.stream.Collectors;

@Service
@Transactional
public class CSRService {

    private final CSRRepository csrRepository;
    private final UserRepository userRepository;
    private final CertificateRepository certificateRepository;
    private final CryptoService cryptoService;

    public CSRService(CSRRepository csrRepository, UserRepository userRepository,
            CertificateRepository certificateRepository, CryptoService cryptoService) {
        this.csrRepository = csrRepository;
        this.userRepository = userRepository;
        this.certificateRepository = certificateRepository;
        this.cryptoService = cryptoService;
    }

    public CSRDTO createCSR(Long userId, CSRRequest request) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("Usuário não encontrado"));

        if (request.getCommonName() == null || request.getCommonName().trim().isEmpty()) {
            throw new IllegalArgumentException("Nome comum é obrigatório");
        }

        if (request.getPublicKey() == null || request.getPublicKey().trim().isEmpty()) {
            throw new IllegalArgumentException("Chave pública é obrigatória");
        }

        CertificateSigningRequest csr = new CertificateSigningRequest();
        csr.setUser(user);
        csr.setCommonName(request.getCommonName().trim());
        csr.setOrganization(request.getOrganization());
        csr.setOrganizationalUnit(request.getOrganizationalUnit());
        csr.setLocality(request.getLocality());
        csr.setProvince(request.getProvince());
        csr.setCountry(request.getCountry());
        csr.setPublicKey(request.getPublicKey());
        csr.setStatus(CertificateSigningRequest.CSRStatus.PENDING);

        CertificateSigningRequest saved = csrRepository.save(csr);
        return toDTO(saved);
    }

    public CSRDTO signCSR(Long csrId, Long caCertificateId, int validDays) {
        CertificateSigningRequest csr = csrRepository.findById(csrId)
                .orElseThrow(() -> new RuntimeException("CSR não encontrado"));

        Certificate caCert = certificateRepository.findById(caCertificateId)
                .orElseThrow(() -> new RuntimeException("Certificado CA não encontrado"));

        if (!caCert.isRootCA() && !isCACertificate(caCert)) {
            throw new RuntimeException("Certificado fornecido não é uma CA");
        }

        if (caCert.getStatus() != Certificate.CertificateStatus.VALID) {
            throw new RuntimeException("Certificado CA não está válido");
        }

        try {
            // Converter chaves
            PublicKey userPublicKey = cryptoService.stringToPublicKey(csr.getPublicKey());
            java.security.PrivateKey caPrivateKey = cryptoService.stringToPrivateKey(caCert.getPrivateKey());

            // ✅ CORREÇÃO: Usar valores padrão se estiverem nulos
            String issuerOrg = caCert.getOrganization() != null ? caCert.getOrganization() : "SecureMessaging CA";
            String issuerOU = caCert.getOrganizationalUnit() != null ? caCert.getOrganizationalUnit()
                    : "Certificate Authority";
            String issuerLocality = caCert.getLocality() != null ? caCert.getLocality() : "Maputo";
            String issuerProvince = caCert.getProvince() != null ? caCert.getProvince() : "Maputo";
            String issuerCountry = caCert.getCountry() != null ? caCert.getCountry() : "MZ";

            // Gerar certificado assinado pela CA
            java.security.cert.X509Certificate signedCert = cryptoService.generateSignedCertificate(
                    userPublicKey, caPrivateKey,
                    csr.getCommonName(),
                    csr.getOrganization() != null ? csr.getOrganization() : "SecureMessaging User",
                    csr.getOrganizationalUnit() != null ? csr.getOrganizationalUnit() : "Users",
                    csr.getLocality() != null ? csr.getLocality() : "Maputo",
                    csr.getProvince() != null ? csr.getProvince() : "Maputo",
                    csr.getCountry() != null ? csr.getCountry() : "MZ",
                    caCert.getSubjectName(), // issuerCommonName
                    issuerOrg, issuerOU, issuerLocality, issuerProvince, issuerCountry,
                    validDays);

            // ✅ CORREÇÃO: Usar getEncoded() corretamente
            String certificateData = Base64.getEncoder().encodeToString(signedCert.getEncoded());

            // Criar entidade Certificate
            Certificate certificate = new Certificate();
            certificate.setUser(csr.getUser());
            certificate.setSubjectName(csr.getCommonName());
            certificate.setIssuerName(caCert.getSubjectName()); // Emitido pela CA
            certificate.setSerialNumber(generateSerialNumber());
            certificate.setPublicKey(csr.getPublicKey());
            // ✅ CORREÇÃO: Salvar dados da organização
            certificate.setOrganization(csr.getOrganization());
            certificate.setOrganizationalUnit(csr.getOrganizationalUnit());
            certificate.setLocality(csr.getLocality());
            certificate.setProvince(csr.getProvince());
            certificate.setCountry(csr.getCountry());
            // ❌ NÃO salva chave privada do usuário (ela fica apenas com o usuário)
            certificate.setCertificateData(certificateData);
            certificate.setSignatureAlgorithm("SHA256withRSA");
            certificate.setValidFrom(LocalDateTime.now());
            certificate.setValidTo(LocalDateTime.now().plusDays(validDays));
            certificate.setStatus(Certificate.CertificateStatus.VALID);
            certificate.setRootCA(false);
            certificate.setCA(false);

            // Assinar com a CA
            String signature = cryptoService.signData(certificate.getCertificateData(), caPrivateKey);
            certificate.setSignature(signature);

            Certificate savedCertificate = certificateRepository.save(certificate);

            // Atualizar CSR
            csr.setStatus(CertificateSigningRequest.CSRStatus.SIGNED);
            csr.setSignedByCA(savedCertificate);
            csrRepository.save(csr);

            return toDTO(csr);
        } catch (Exception e) {
            throw new RuntimeException("Erro ao assinar CSR: " + e.getMessage(), e);
        }
    }

    public CSRDTO approveCSR(Long csrId) {
        CertificateSigningRequest csr = csrRepository.findById(csrId)
                .orElseThrow(() -> new RuntimeException("CSR não encontrado"));

        csr.setStatus(CertificateSigningRequest.CSRStatus.APPROVED);
        CertificateSigningRequest saved = csrRepository.save(csr);
        return toDTO(saved);
    }

    public CSRDTO rejectCSR(Long csrId, String reason) {
        CertificateSigningRequest csr = csrRepository.findById(csrId)
                .orElseThrow(() -> new RuntimeException("CSR não encontrado"));

        csr.setStatus(CertificateSigningRequest.CSRStatus.REJECTED);
        csr.setRejectionReason(reason);
        CertificateSigningRequest saved = csrRepository.save(csr);
        return toDTO(saved);
    }

    public List<CSRDTO> getCSRsByUser(Long userId) {
        return csrRepository.findByUserId(userId).stream()
                .map(this::toDTO)
                .collect(Collectors.toList());
    }

    public List<CSRDTO> getPendingCSRs() {
        return csrRepository.findByStatus(CertificateSigningRequest.CSRStatus.PENDING).stream()
                .map(this::toDTO)
                .collect(Collectors.toList());
    }

    public CSRDTO getCSRById(Long csrId) {
        return csrRepository.findById(csrId)
                .map(this::toDTO)
                .orElseThrow(() -> new RuntimeException("CSR não encontrado"));
    }

    private boolean isCACertificate(Certificate cert) {
        // Lógica para verificar se é CA (pode ser baseada em extensions)
        return cert.isRootCA() || cert.isCA() || cert.getSubjectName().contains("CA");
    }

    private String generateSerialNumber() {
        return "SN-" + System.currentTimeMillis() + "-" +
                java.util.UUID.randomUUID().toString().substring(0, 8).toUpperCase();
    }

    private CSRDTO toDTO(CertificateSigningRequest csr) {
        if (csr == null)
            return null;

        CSRDTO dto = new CSRDTO();
        dto.setId(csr.getId());
        dto.setUserId(csr.getUser().getId());
        dto.setCommonName(csr.getCommonName());
        dto.setOrganization(csr.getOrganization());
        dto.setOrganizationalUnit(csr.getOrganizationalUnit());
        dto.setLocality(csr.getLocality());
        dto.setProvince(csr.getProvince());
        dto.setCountry(csr.getCountry());
        dto.setPublicKey(csr.getPublicKey());
        dto.setStatus(csr.getStatus().toString());
        dto.setRejectionReason(csr.getRejectionReason());
        dto.setCreatedAt(csr.getCreatedAt());
        dto.setUpdatedAt(csr.getUpdatedAt());

        if (csr.getSignedByCA() != null) {
            dto.setSignedByCAId(csr.getSignedByCA().getId());
            dto.setSignedByCAName(csr.getSignedByCA().getSubjectName());
        }

        return dto;
    }
}