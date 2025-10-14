// src/main/java/com/securemessaging/controller/CSRController.java
package com.securemessaging.controller;

import com.securemessaging.dto.CSRDTO;
import com.securemessaging.dto.CSRRequest;
import com.securemessaging.service.CSRService;
import com.securemessaging.repository.UserRepository;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/csrs")
@CrossOrigin(origins = "*")
@Tag(name = "Certificate Signing Requests", description = "API para gestão de pedidos de assinatura de certificados")
public class CSRController {

    private final CSRService csrService;
    private final UserRepository userRepository;

    public CSRController(CSRService csrService, UserRepository userRepository) {
        this.csrService = csrService;
        this.userRepository = userRepository;
    }

    @Operation(summary = "Criar CSR", description = "Cria um pedido de assinatura de certificado")
    @PostMapping
    public ResponseEntity<?> createCSR(@RequestBody CSRRequest request) {
        try {
            if (request.getCommonName() == null || request.getCommonName().trim().isEmpty()) {
                return ResponseEntity.badRequest().body(Map.of(
                        "success", false,
                        "error", "Nome comum é obrigatório"));
            }

            if (request.getPublicKey() == null || request.getPublicKey().trim().isEmpty()) {
                return ResponseEntity.badRequest().body(Map.of(
                        "success", false,
                        "error", "Chave pública é obrigatória"));
            }

            Long userId = extractUserIdFromAuth();
            CSRDTO csr = csrService.createCSR(userId, request);

            return ResponseEntity.ok(Map.of(
                    "success", true,
                    "message", "CSR criado com sucesso",
                    "csr", csr));
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(Map.of(
                    "success", false,
                    "error", e.getMessage()));
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of(
                            "success", false,
                            "error", "Erro interno ao criar CSR: " + e.getMessage()));
        }
    }

    @Operation(summary = "Assinar CSR", description = "Assina um CSR com uma CA existente")
    @PostMapping("/{csrId}/sign/{caCertificateId}")
    public ResponseEntity<?> signCSR(
            @PathVariable Long csrId,
            @PathVariable Long caCertificateId,
            @RequestBody Map<String, Object> request) {
        try {
            int validDays = (int) request.getOrDefault("validDays", 365);

            CSRDTO signedCSR = csrService.signCSR(csrId, caCertificateId, validDays);

            return ResponseEntity.ok(Map.of(
                    "success", true,
                    "message", "CSR assinado com sucesso",
                    "csr", signedCSR));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of(
                    "success", false,
                    "error", e.getMessage()));
        }
    }

    @Operation(summary = "Aprovar CSR", description = "Aprova um CSR pendente")
    @PutMapping("/{csrId}/approve")
    public ResponseEntity<?> approveCSR(@PathVariable Long csrId) {
        try {
            CSRDTO approvedCSR = csrService.approveCSR(csrId);

            return ResponseEntity.ok(Map.of(
                    "success", true,
                    "message", "CSR aprovado com sucesso",
                    "csr", approvedCSR));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of(
                    "success", false,
                    "error", e.getMessage()));
        }
    }

    @Operation(summary = "Rejeitar CSR", description = "Rejeita um CSR pendente")
    @PutMapping("/{csrId}/reject")
    public ResponseEntity<?> rejectCSR(
            @PathVariable Long csrId,
            @RequestBody Map<String, String> request) {
        try {
            String reason = request.getOrDefault("reason", "Rejeitado pela administração");

            CSRDTO rejectedCSR = csrService.rejectCSR(csrId, reason);

            return ResponseEntity.ok(Map.of(
                    "success", true,
                    "message", "CSR rejeitado com sucesso",
                    "csr", rejectedCSR));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of(
                    "success", false,
                    "error", e.getMessage()));
        }
    }

    @Operation(summary = "Listar CSRs do usuário", description = "Lista todos os CSRs do usuário autenticado")
    @GetMapping("/my-csrs")
    public ResponseEntity<?> getMyCSRs() {
        try {
            Long userId = extractUserIdFromAuth();
            List<CSRDTO> csrs = csrService.getCSRsByUser(userId);

            return ResponseEntity.ok(Map.of(
                    "success", true,
                    "csrs", csrs,
                    "count", csrs.size()));
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of(
                            "success", false,
                            "error", "Erro ao buscar CSRs: " + e.getMessage()));
        }
    }

    @Operation(summary = "Listar CSRs pendentes", description = "Lista todos os CSRs pendentes (para administração)")
    @GetMapping("/pending")
    public ResponseEntity<?> getPendingCSRs() {
        try {
            List<CSRDTO> pendingCSRs = csrService.getPendingCSRs();

            return ResponseEntity.ok(Map.of(
                    "success", true,
                    "pendingCSRs", pendingCSRs,
                    "count", pendingCSRs.size()));
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of(
                            "success", false,
                            "error", "Erro ao buscar CSRs pendentes: " + e.getMessage()));
        }
    }

    @Operation(summary = "Buscar CSR por ID")
    @GetMapping("/{csrId}")
    public ResponseEntity<?> getCSRById(@PathVariable Long csrId) {
        try {
            CSRDTO csr = csrService.getCSRById(csrId);

            return ResponseEntity.ok(Map.of(
                    "success", true,
                    "csr", csr));
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body(Map.of(
                            "success", false,
                            "error", e.getMessage()));
        }
    }

    @Operation(summary = "Health check")
    @GetMapping("/health")
    public ResponseEntity<?> healthCheck() {
        try {
            Long userId = extractUserIdFromAuth();
            List<CSRDTO> userCSRs = csrService.getCSRsByUser(userId);
            List<CSRDTO> pendingCSRs = csrService.getPendingCSRs();

            return ResponseEntity.ok(Map.of(
                    "status", "UP",
                    "service", "CSR Management",
                    "userCSRsCount", userCSRs.size(),
                    "pendingCSRsCount", pendingCSRs.size(),
                    "timestamp", java.time.LocalDateTime.now()));
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of(
                            "status", "DOWN",
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

            return userRepository.findByUsername(username)
                    .map(user -> user.getId())
                    .orElseThrow(() -> new RuntimeException("Usuário não encontrado: " + username));

        } catch (Exception e) {
            throw new RuntimeException("Erro ao obter ID do usuário: " + e.getMessage());
        }
    }
}