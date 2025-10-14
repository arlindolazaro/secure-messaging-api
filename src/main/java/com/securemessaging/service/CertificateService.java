package com.securemessaging.service;

import com.securemessaging.dto.CertificateDTO;
import com.securemessaging.dto.CertificateRequest;
import com.securemessaging.model.Certificate;
import com.securemessaging.model.User;
import com.securemessaging.repository.CertificateRepository;
import com.securemessaging.repository.UserRepository;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.KeyPair;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.time.LocalDateTime;
import java.util.*;
import java.util.stream.Collectors;

@Service
@Transactional
public class CertificateService {

    private final CertificateRepository certificateRepository;
    private final UserRepository userRepository;
    private final CryptoService cryptoService;

    public CertificateService(CertificateRepository certificateRepository,
            UserRepository userRepository,
            CryptoService cryptoService) {
        this.certificateRepository = certificateRepository;
        this.userRepository = userRepository;
        this.cryptoService = cryptoService;
    }

    public CertificateDTO generateRootCA(Long userId, CertificateRequest request) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("Usuário não encontrado com ID: " + userId));

        if (request.getCommonName() == null || request.getCommonName().trim().isEmpty()) {
            throw new IllegalArgumentException("Nome comum é obrigatório para Root CA");
        }

        try {
            // Gerar par de chaves RSA 1024 bits
            KeyPair keyPair = cryptoService.generateRSAKeyPair(1024);

            int validYears = request.getValidYears() != null ? request.getValidYears() : 10;
            int validDays = validYears * 365;

            // ✅ CORREÇÃO: Usar valores padrão se estiverem nulos
            String organization = request.getOrganization() != null ? request.getOrganization().trim()
                    : "SecureMessaging Root CA";
            String organizationalUnit = request.getOrganizationalUnit() != null ? request.getOrganizationalUnit().trim()
                    : "Certificate Authority";
            String locality = request.getLocality() != null ? request.getLocality().trim() : "Maputo";
            String province = request.getProvince() != null ? request.getProvince().trim() : "Maputo";
            String country = request.getCountry() != null ? request.getCountry().trim() : "MZ";

            X509Certificate rootCert = cryptoService.generateRootCertificate(
                    keyPair,
                    request.getCommonName().trim(),
                    organization,
                    organizationalUnit,
                    locality,
                    province,
                    country,
                    validDays);

            Certificate root = new Certificate();
            root.setUser(user);
            root.setSubjectName(request.getCommonName().trim());
            root.setIssuerName(request.getCommonName().trim()); // Self-signed
            root.setSerialNumber(generateSerialNumber());
            root.setPublicKey(Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded()));
            root.setPrivateKey(Base64.getEncoder().encodeToString(keyPair.getPrivate().getEncoded()));
            root.setCertificateData(Base64.getEncoder().encodeToString(rootCert.getEncoded()));
            root.setSignatureAlgorithm("SHA256withRSA");
            root.setValidFrom(LocalDateTime.now());
            root.setValidTo(LocalDateTime.now().plusYears(validYears));
            root.setStatus(Certificate.CertificateStatus.VALID);
            root.setRootCA(true);
            root.setCA(true); // ✅ É uma CA

            // ✅ CORREÇÃO: Salvar dados da organização
            root.setOrganization(organization);
            root.setOrganizationalUnit(organizationalUnit);
            root.setLocality(locality);
            root.setProvince(province);
            root.setCountry(country);

            // Assinar o certificado
            String signature = cryptoService.signData(root.getCertificateData(), keyPair.getPrivate());
            root.setSignature(signature);

            Certificate saved = certificateRepository.save(root);
            return toDTO(saved);
        } catch (Exception e) {
            throw new RuntimeException("Erro ao gerar Root CA: " + e.getMessage(), e);
        }
    }

    public CertificateDTO createCertificate(Long userId, CertificateRequest request) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("Usuário não encontrado com ID: " + userId));

        if (request.getCommonName() == null || request.getCommonName().trim().isEmpty()) {
            throw new IllegalArgumentException("Nome comum (commonName) é obrigatório");
        }

        try {
            KeyPair keyPair = cryptoService.generateRSAKeyPair(1024);
            int validDays = request.getValidDays() != null ? request.getValidDays() : 365;

            X509Certificate x509Cert = cryptoService.generateCertificate(
                    keyPair,
                    request.getCommonName().trim(),
                    request.getOrganization() != null ? request.getOrganization().trim() : "SecureMessaging",
                    request.getOrganizationalUnit() != null ? request.getOrganizationalUnit().trim() : "Users",
                    request.getLocality() != null ? request.getLocality().trim() : "Maputo",
                    request.getProvince() != null ? request.getProvince().trim() : "Maputo",
                    request.getCountry() != null ? request.getCountry().trim() : "MZ",
                    validDays);

            Certificate certificate = new Certificate();
            certificate.setUser(user);
            certificate.setSubjectName(request.getCommonName().trim());
            certificate.setIssuerName(request.getCommonName().trim());
            certificate.setSerialNumber(generateSerialNumber());
            certificate.setPublicKey(Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded()));
            certificate.setPrivateKey(Base64.getEncoder().encodeToString(keyPair.getPrivate().getEncoded()));
            certificate.setCertificateData(Base64.getEncoder().encodeToString(x509Cert.getEncoded()));
            certificate.setSignatureAlgorithm("SHA256withRSA");
            certificate.setValidFrom(LocalDateTime.now());
            certificate.setValidTo(LocalDateTime.now().plusDays(validDays));
            certificate.setStatus(Certificate.CertificateStatus.VALID);
            certificate.setRootCA(false);
            certificate.setCA(false);
            certificate.setOrganization(request.getOrganization());
            certificate.setOrganizationalUnit(request.getOrganizationalUnit());
            certificate.setLocality(request.getLocality());
            certificate.setProvince(request.getProvince());
            certificate.setCountry(request.getCountry());

            String signature = cryptoService.signData(certificate.getCertificateData(), keyPair.getPrivate());
            certificate.setSignature(signature);

            Certificate saved = certificateRepository.save(certificate);
            return toDTO(saved);
        } catch (Exception e) {
            throw new RuntimeException("Erro ao gerar certificado: " + e.getMessage(), e);
        }
    }

    public Optional<CertificateDTO> getUserRootCertificate(Long userId) {
        try {
            List<Certificate> rootCAs = certificateRepository.findByUserId(userId)
                    .stream()
                    .filter(Certificate::isRootCA)
                    .collect(Collectors.toList());

            if (rootCAs.isEmpty()) {
                return Optional.empty();
            }

            Certificate latestRootCA = rootCAs.stream()
                    .max(Comparator.comparing(Certificate::getCreatedAt))
                    .orElse(rootCAs.get(0));

            return Optional.of(toDTO(latestRootCA));
        } catch (Exception e) {
            System.err.println("Erro ao buscar Root CA do utilizador: " + e.getMessage());
            return Optional.empty();
        }
    }

    public CertificateDTO signCertificate(Long certificateId, Long caCertificateId) {
        try {
            Certificate certToSign = certificateRepository.findById(certificateId)
                    .orElseThrow(() -> new RuntimeException("Certificado a ser assinado não encontrado"));

            Certificate caCert = certificateRepository.findById(caCertificateId)
                    .orElseThrow(() -> new RuntimeException("Certificado CA não encontrado"));

            if (caCert.getStatus() == Certificate.CertificateStatus.REVOKED) {
                throw new RuntimeException("Certificado CA está revogado");
            }

            if (!isCertificateWithinValidity(caCert)) {
                throw new RuntimeException("Certificado CA expirado");
            }

            if (!caCert.isRootCA()) {
                throw new RuntimeException("Certificado fornecido não é uma CA");
            }

            java.security.PrivateKey caPrivateKey = cryptoService.stringToPrivateKey(caCert.getPrivateKey());
            String signature = cryptoService.signData(certToSign.getCertificateData(), caPrivateKey);

            certToSign.setSignature(signature);
            certToSign.setIssuerName(caCert.getSubjectName());
            certToSign.setStatus(Certificate.CertificateStatus.VALID);

            Certificate signedCert = certificateRepository.save(certToSign);
            return toDTO(signedCert);
        } catch (Exception e) {
            throw new RuntimeException("Erro ao assinar certificado: " + e.getMessage(), e);
        }
    }

    public Map<String, Object> verifyCertificate(Long certificateId) {
        try {
            Certificate cert = certificateRepository.findById(certificateId)
                    .orElseThrow(() -> new RuntimeException("Certificado não encontrado"));

            boolean isSignatureValid = verifyCertificateSignature(cert);
            boolean isNotRevoked = cert.getStatus() != Certificate.CertificateStatus.REVOKED;
            boolean isWithinValidity = isCertificateWithinValidity(cert);
            boolean isChainValid = true;

            if (!cert.getIssuerName().equals(cert.getSubjectName())) {
                isChainValid = verifyCertificateChain(cert);
            }

            boolean overallValid = isSignatureValid && isNotRevoked && isWithinValidity && isChainValid;

            Map<String, Object> result = new HashMap<>();
            result.put("valid", overallValid);
            result.put("signatureValid", isSignatureValid);
            result.put("notRevoked", isNotRevoked);
            result.put("withinValidity", isWithinValidity);
            result.put("chainValid", isChainValid);
            result.put("message", overallValid ? "Certificado válido" : "Certificado inválido");
            result.put("certificateId", certificateId);
            result.put("subject", cert.getSubjectName());
            result.put("issuer", cert.getIssuerName());
            result.put("validationTime", LocalDateTime.now());

            return result;
        } catch (Exception e) {
            Map<String, Object> result = new HashMap<>();
            result.put("valid", false);
            result.put("signatureValid", false);
            result.put("notRevoked", false);
            result.put("withinValidity", false);
            result.put("chainValid", false);
            result.put("message", "Erro na verificação: " + e.getMessage());
            return result;
        }
    }

    public Map<String, Object> verifyCertificateIntegrity(Long certificateId) {
        try {
            Certificate cert = certificateRepository.findById(certificateId)
                    .orElseThrow(() -> new RuntimeException("Certificado não encontrado"));

            String certificateHash = cryptoService.hashWithSHA256(cert.getCertificateData());

            boolean integrityValid = cryptoService.verifySignature(
                    cert.getCertificateData(),
                    cert.getSignature(),
                    cryptoService.stringToPublicKey(cert.getPublicKey()));

            Map<String, Object> result = new HashMap<>();
            result.put("certificateId", certificateId);
            result.put("integrityValid", integrityValid);
            result.put("certificateHash", certificateHash);
            result.put("signatureAlgorithm", cert.getSignatureAlgorithm());
            result.put("verifiedAt", LocalDateTime.now());

            return result;
        } catch (Exception e) {
            Map<String, Object> result = new HashMap<>();
            result.put("integrityValid", false);
            result.put("error", e.getMessage());
            return result;
        }
    }

    @Scheduled(fixedRate = 86400000)
    public void updateExpiredCertificates() {
        try {
            List<Certificate> validCertificates = certificateRepository.findValidCertificates();
            LocalDateTime now = LocalDateTime.now();
            int updatedCount = 0;

            for (Certificate cert : validCertificates) {
                if (now.isAfter(cert.getValidTo())) {
                    cert.setStatus(Certificate.CertificateStatus.EXPIRED);
                    certificateRepository.save(cert);
                    updatedCount++;
                }
            }

            System.out.println("Certificados expirados atualizados: " + updatedCount);
        } catch (Exception e) {
            System.err.println("Erro ao atualizar certificados expirados: " + e.getMessage());
        }
    }

    private boolean verifyCertificateSignature(Certificate cert) {
        try {
            if (cert.getSignature() == null)
                return false;
            X509Certificate x509Cert = (X509Certificate) java.security.cert.CertificateFactory
                    .getInstance("X.509")
                    .generateCertificate(
                            new java.io.ByteArrayInputStream(Base64.getDecoder().decode(cert.getCertificateData())));
            x509Cert.verify(x509Cert.getPublicKey());
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    private boolean verifyCertificateChain(Certificate cert) {
        try {
            List<Certificate> issuerCerts = certificateRepository.findBySubjectName(cert.getIssuerName());
            if (issuerCerts.isEmpty())
                return false;

            Certificate issuerCert = issuerCerts.get(0);
            PublicKey issuerPublicKey = cryptoService.stringToPublicKey(issuerCert.getPublicKey());

            X509Certificate x509Cert = (X509Certificate) java.security.cert.CertificateFactory
                    .getInstance("X.509")
                    .generateCertificate(
                            new java.io.ByteArrayInputStream(Base64.getDecoder().decode(cert.getCertificateData())));

            x509Cert.verify(issuerPublicKey);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    private boolean isCertificateWithinValidity(Certificate cert) {
        if (cert == null)
            return false;
        LocalDateTime now = LocalDateTime.now();
        return (now.isAfter(cert.getValidFrom()) || now.isEqual(cert.getValidFrom()))
                && now.isBefore(cert.getValidTo());
    }

    public Optional<CertificateDTO> getCertificateById(Long certificateId) {
        try {
            Optional<Certificate> certificate = certificateRepository.findById(certificateId);
            return certificate.map(this::toDTO);
        } catch (Exception e) {
            return Optional.empty();
        }
    }

    public List<CertificateDTO> getCertificatesByUser(Long userId) {
        try {
            List<Certificate> certificates = certificateRepository.findByUserId(userId);
            return certificates.stream().map(this::toDTO).collect(Collectors.toList());
        } catch (Exception e) {
            throw new RuntimeException("Erro ao buscar certificados: " + e.getMessage(), e);
        }
    }

    public List<CertificateDTO> getAllCertificates() {
        try {
            List<Certificate> certificates = certificateRepository.findAll();
            return certificates.stream().map(this::toDTO).collect(Collectors.toList());
        } catch (Exception e) {
            return Collections.emptyList();
        }
    }

    public List<CertificateDTO> getRootCertificates() {
        try {
            List<Certificate> rootCerts = certificateRepository.findAllRootCertificates();
            return rootCerts.stream().map(this::toDTO).collect(Collectors.toList());
        } catch (Exception e) {
            return Collections.emptyList();
        }
    }

    public Optional<CertificateDTO> getValidUserCertificate(Long userId) {
        try {
            Optional<Certificate> validCert = certificateRepository.findValidCertificateByUser(userId);
            return validCert.map(this::toDTO);
        } catch (Exception e) {
            return Optional.empty();
        }
    }

    public CertificateDTO revokeCertificate(Long certificateId, String reason) {
        try {
            Certificate cert = certificateRepository.findById(certificateId)
                    .orElseThrow(() -> new RuntimeException("Certificado não encontrado"));

            if (cert.getStatus() == Certificate.CertificateStatus.REVOKED) {
                throw new RuntimeException("Certificado já está revogado");
            }

            cert.setStatus(Certificate.CertificateStatus.REVOKED);
            cert.setRevokedAt(LocalDateTime.now());
            cert.setRevocationReason(reason);

            Certificate updated = certificateRepository.save(cert);
            return toDTO(updated);
        } catch (Exception e) {
            throw new RuntimeException("Erro ao revogar certificado: " + e.getMessage(), e);
        }
    }

    // ✅ Método atualizado
    private CertificateDTO toDTO(Certificate cert) {
        if (cert == null)
            return null;

        CertificateDTO dto = new CertificateDTO();
        dto.setId(cert.getId());
        dto.setUserId(cert.getUser() != null ? cert.getUser().getId() : null);
        dto.setSubjectName(cert.getSubjectName());
        dto.setIssuerName(cert.getIssuerName());
        dto.setSerialNumber(cert.getSerialNumber());
        dto.setPublicKey(cert.getPublicKey());
        dto.setSignature(cert.getSignature());
        dto.setSignatureAlgorithm(cert.getSignatureAlgorithm());
        dto.setValidFrom(cert.getValidFrom());
        dto.setValidTo(cert.getValidTo());
        dto.setStatus(cert.getStatus().toString());
        dto.setRootCA(cert.isRootCA());
        dto.setCreatedAt(cert.getCreatedAt());
        dto.setRevokedAt(cert.getRevokedAt());
        dto.setRevocationReason(cert.getRevocationReason());

        // ✅ Novos campos PKI completos
        dto.setOrganization(cert.getOrganization());
        dto.setOrganizationalUnit(cert.getOrganizationalUnit());
        dto.setLocality(cert.getLocality());
        dto.setProvince(cert.getProvince());
        dto.setCountry(cert.getCountry());
        dto.setEmail(cert.getEmail());
        dto.setCA(cert.isCA());
        dto.setKeyUsage(cert.getKeyUsage());

        return dto;
    }

    private String generateSerialNumber() {
        return "SN-" + System.currentTimeMillis() + "-" + UUID.randomUUID().toString().substring(0, 8).toUpperCase();
    }
}
