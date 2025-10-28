package com.securemessaging.controller;

import com.securemessaging.dto.CertificateDTO;
import com.securemessaging.dto.CertificateRequest;
import com.securemessaging.repository.UserRepository;
import com.securemessaging.service.CertificateService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;
import java.util.Optional;

@RestController
@RequestMapping("/api/certificates")
@CrossOrigin(origins = "*")
@Tag(name = "Certificates", description = "API para gestão de certificados PKI")
public class CertificateController {

    private final CertificateService certificateService;
    private final UserRepository userRepository;

    public CertificateController(CertificateService certificateService,
            UserRepository userRepository) {
        this.certificateService = certificateService;
        this.userRepository = userRepository;
    }

    @Operation(summary = "Criar certificado", description = "Cria novo certificado X.509 para o utilizador autenticado")
    @PostMapping
    public ResponseEntity<?> createCertificate(@RequestBody CertificateRequest request) {
        try {
            if (request.getCommonName() == null || request.getCommonName().trim().isEmpty()) {
                return ResponseEntity.badRequest().body(Map.of(
                        "success", false,
                        "error", "Nome comum é obrigatório"));
            }

            Long userId = extractUserIdFromAuth();
            CertificateDTO certificate = certificateService.createCertificate(userId, request);

            return ResponseEntity.ok(Map.of(
                    "success", true,
                    "message", "Certificado criado com sucesso",
                    "certificate", certificate));
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(Map.of(
                    "success", false,
                    "error", e.getMessage()));
        } catch (Exception e) {
            e.printStackTrace(); // ✅ LOG PARA DEBUG
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of(
                            "success", false,
                            "error", "Erro interno ao criar certificado: " + e.getMessage()));
        }
    }

    @Operation(summary = "Gerar Root CA", description = "Gera certificado Root CA autoassinado")
    @PostMapping("/root")
    public ResponseEntity<?> generateRootCA(@RequestBody CertificateRequest request) {
        try {
            if (request.getCommonName() == null || request.getCommonName().trim().isEmpty()) {
                return ResponseEntity.badRequest().body(Map.of(
                        "success", false,
                        "error", "Nome comum é obrigatório para Root CA"));
            }

            Long userId = extractUserIdFromAuth();
            CertificateDTO rootCA = certificateService.generateRootCA(userId, request);

            return ResponseEntity.ok(Map.of(
                    "success", true,
                    "message", "Root CA gerado com sucesso",
                    "rootCA", rootCA));
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(Map.of(
                    "success", false,
                    "error", e.getMessage()));
        } catch (Exception e) {
            e.printStackTrace(); // ✅ LOG PARA DEBUG
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of(
                            "success", false,
                            "error", "Erro interno ao gerar Root CA: " + e.getMessage()));
        }
    }

    @Operation(summary = "Assinar certificado", description = "Assina certificado com CA existente")
    @PostMapping("/{certificateId}/sign/{caCertificateId}")
    public ResponseEntity<?> signCertificate(
            @PathVariable Long certificateId,
            @PathVariable Long caCertificateId) {
        try {
            CertificateDTO signedCert = certificateService.signCertificate(certificateId, caCertificateId);
            return ResponseEntity.ok(Map.of(
                    "success", true,
                    "message", "Certificado assinado com sucesso",
                    "certificate", signedCert));
        } catch (Exception e) {
            e.printStackTrace(); // ✅ LOG PARA DEBUG
            return ResponseEntity.badRequest().body(Map.of(
                    "success", false,
                    "error", e.getMessage()));
        }
    }

    @Operation(summary = "Verificar certificado", description = "Verifica validade e integridade do certificado")
    @GetMapping("/{certificateId}/verify")
    public ResponseEntity<?> verifyCertificate(@PathVariable Long certificateId) {
        try {
            Map<String, Object> result = certificateService.verifyCertificate(certificateId);
            return ResponseEntity.ok(Map.of(
                    "success", true,
                    "verification", result));
        } catch (Exception e) {
            e.printStackTrace(); // ✅ LOG PARA DEBUG
            return ResponseEntity.badRequest().body(Map.of(
                    "success", false,
                    "error", e.getMessage()));
        }
    }

    @Operation(summary = "Verificar integridade", description = "Verifica integridade do certificado com SHA-256")
    @GetMapping("/{certificateId}/verify-integrity")
    public ResponseEntity<?> verifyCertificateIntegrity(@PathVariable Long certificateId) {
        try {
            Map<String, Object> result = certificateService.verifyCertificateIntegrity(certificateId);
            return ResponseEntity.ok(Map.of(
                    "success", true,
                    "integrityCheck", result));
        } catch (Exception e) {
            e.printStackTrace(); // ✅ LOG PARA DEBUG
            return ResponseEntity.badRequest().body(Map.of(
                    "success", false,
                    "error", e.getMessage()));
        }
    }

    @Operation(summary = "Listar certificados", description = "Lista todos os certificados do sistema")
    @GetMapping
    public ResponseEntity<?> getAllCertificates() {
        try {
            List<CertificateDTO> certificates = certificateService.getAllCertificates();
            return ResponseEntity.ok(Map.of(
                    "success", true,
                    "certificates", certificates,
                    "count", certificates.size()));
        } catch (Exception e) {
            e.printStackTrace(); // ✅ LOG PARA DEBUG
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of(
                            "success", false,
                            "error", "Erro ao buscar certificados: " + e.getMessage()));
        }
    }

    @Operation(summary = "Buscar certificado por ID")
    @GetMapping("/{certificateId}")
    public ResponseEntity<?> getCertificateById(@PathVariable Long certificateId) {
        try {
            Optional<CertificateDTO> certificate = certificateService.getCertificateById(certificateId);
            if (certificate.isPresent()) {
                return ResponseEntity.ok(Map.of(
                        "success", true,
                        "certificate", certificate.get()));
            } else {
                return ResponseEntity.status(HttpStatus.NOT_FOUND)
                        .body(Map.of(
                                "success", false,
                                "error", "Certificado não encontrado"));
            }
        } catch (Exception e) {
            e.printStackTrace(); // ✅ LOG PARA DEBUG
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of(
                            "success", false,
                            "error", "Erro ao buscar certificado: " + e.getMessage()));
        }
    }

    @Operation(summary = "Certificados do utilizador autenticado")
    @GetMapping("/my-certificates")
    public ResponseEntity<?> getMyCertificates() {
        try {
            Long userId = extractUserIdFromAuth();
            System.out.println("✅ Buscando certificados para userId: " + userId); // ✅ DEBUG

            List<CertificateDTO> certificates = certificateService.getCertificatesByUser(userId);
            System.out.println("✅ Certificados encontrados: " + certificates.size()); // ✅ DEBUG

            return ResponseEntity.ok(Map.of(
                    "success", true,
                    "certificates", certificates,
                    "count", certificates.size()));
        } catch (Exception e) {
            e.printStackTrace(); // ✅ LOG DETALHADO
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of(
                            "success", false,
                            "error", "Erro ao buscar certificados: " + e.getMessage()));
        }
    }

    @Operation(summary = "Certificado válido do utilizador")
    @GetMapping("/my-valid-certificate")
    public ResponseEntity<?> getMyValidCertificate() {
        try {
            Long userId = extractUserIdFromAuth();
            Optional<CertificateDTO> certificate = certificateService.getValidUserCertificate(userId);

            if (certificate.isPresent()) {
                return ResponseEntity.ok(Map.of(
                        "success", true,
                        "hasValidCertificate", true,
                        "certificate", certificate.get()));
            } else {
                return ResponseEntity.ok(Map.of(
                        "success", true,
                        "hasValidCertificate", false,
                        "message", "Nenhum certificado válido encontrado"));
            }
        } catch (Exception e) {
            e.printStackTrace(); // ✅ LOG PARA DEBUG
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of(
                            "success", false,
                            "error", "Erro ao buscar certificado válido: " + e.getMessage()));
        }
    }

    @Operation(summary = "Apagar certificado", description = "Apaga um certificado (apenas o dono pode apagar)")
    @DeleteMapping("/{certificateId}")
    public ResponseEntity<?> deleteCertificate(@PathVariable Long certificateId) {
        try {
            Long userId = extractUserIdFromAuth();
            certificateService.deleteCertificate(certificateId, userId);
            return ResponseEntity.ok(Map.of(
                    "success", true,
                    "message", "Certificado apagado com sucesso",
                    "certificateId", certificateId));
        } catch (Exception e) {
            e.printStackTrace();
            String msg = e.getMessage() != null ? e.getMessage() : "Erro ao apagar certificado";
            if (msg.contains("solicitações de assinatura") || msg.contains("referenciando esta CA")) {
                return ResponseEntity.status(HttpStatus.CONFLICT).body(Map.of(
                        "success", false,
                        "error", msg));
            }

            return ResponseEntity.status(HttpStatus.FORBIDDEN).body(Map.of(
                    "success", false,
                    "error", msg));
        }
    }

    @Operation(summary = "Certificados Root CA")
    @GetMapping("/roots")
    public ResponseEntity<?> getRootCertificates() {
        try {
            List<CertificateDTO> rootCerts = certificateService.getRootCertificates();
            return ResponseEntity.ok(Map.of(
                    "success", true,
                    "rootCertificates", rootCerts,
                    "count", rootCerts.size()));
        } catch (Exception e) {
            e.printStackTrace(); // ✅ LOG PARA DEBUG
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of(
                            "success", false,
                            "error", "Erro ao buscar certificados Root: " + e.getMessage()));
        }
    }

    @Operation(summary = "Root CA do utilizador")
    @GetMapping("/my-root-ca")
    public ResponseEntity<?> getMyRootCertificate() {
        try {
            Long userId = extractUserIdFromAuth();
            Optional<CertificateDTO> rootCA = certificateService.getUserRootCertificate(userId);

            if (rootCA.isPresent()) {
                return ResponseEntity.ok(Map.of(
                        "success", true,
                        "rootCA", rootCA.get()));
            } else {
                return ResponseEntity.status(HttpStatus.NOT_FOUND)
                        .body(Map.of(
                                "success", false,
                                "message", "Nenhum Root CA encontrado para o seu usuário"));
            }
        } catch (Exception e) {
            e.printStackTrace(); // ✅ LOG PARA DEBUG
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of(
                            "success", false,
                            "error", "Erro ao buscar Root CA: " + e.getMessage()));
        }
    }

    @Operation(summary = "Revogar certificado", description = "Revoga certificado com motivo específico")
    @PutMapping("/{certificateId}/revoke")
    public ResponseEntity<?> revokeCertificate(
            @PathVariable Long certificateId,
            @RequestBody Map<String, String> request) {
        try {
            String reason = request.getOrDefault("reason", "Revogado pelo utilizador");
            CertificateDTO revokedCert = certificateService.revokeCertificate(certificateId, reason);
            return ResponseEntity.ok(Map.of(
                    "success", true,
                    "message", "Certificado revogado com sucesso",
                    "certificate", revokedCert));
        } catch (Exception e) {
            e.printStackTrace(); // ✅ LOG PARA DEBUG
            return ResponseEntity.badRequest().body(Map.of(
                    "success", false,
                    "error", e.getMessage()));
        }
    }

    @Operation(summary = "Health check")
    @GetMapping("/health")
    public ResponseEntity<?> healthCheck() {
        try {
            List<CertificateDTO> certificates = certificateService.getAllCertificates();
            return ResponseEntity.ok(Map.of(
                    "status", "UP",
                    "success", true,
                    "totalCertificates", certificates.size(),
                    "timestamp", java.time.LocalDateTime.now()));
        } catch (Exception e) {
            e.printStackTrace(); // ✅ LOG PARA DEBUG
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of(
                            "status", "DOWN",
                            "success", false,
                            "error", e.getMessage()));
        }
    }

    private Long extractUserIdFromAuth() {
        try {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

            if (authentication == null || !authentication.isAuthenticated()) {
                throw new RuntimeException("Usuário não autenticado");
            }

            String username = authentication.getName();
            System.out.println("✅ Usuário autenticado: " + username); // ✅ DEBUG

            return userRepository.findByUsername(username)
                    .map(user -> {
                        System.out.println("✅ ID do usuário encontrado: " + user.getId()); // ✅ DEBUG
                        return user.getId();
                    })
                    .orElseThrow(() -> new RuntimeException("Usuário não encontrado: " + username));

        } catch (Exception e) {
            System.err.println("❌ Erro ao obter ID do usuário: " + e.getMessage());
            e.printStackTrace();
            throw new RuntimeException("Erro ao obter ID do usuário: " + e.getMessage());
        }
    }
}