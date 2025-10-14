package com.securemessaging.controller;

import com.securemessaging.dto.KeyManagementDTO;
import com.securemessaging.service.KeyManagementService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/key-management")
@CrossOrigin(origins = "*")
@Tag(name = "Key Management", description = "API para gestão de chaves criptográficas")
public class KeyManagementController {

    @Autowired
    private KeyManagementService keyManagementService;

    @Operation(summary = "Gerar novo par de chaves RSA", description = "Gera novo par de chaves RSA para o utilizador")
    @PostMapping("/users/{userId}/generate-keys")
    public ResponseEntity<?> generateKeyPair(@PathVariable Long userId,
            @RequestParam(defaultValue = "1024") int keySize) {
        try {
            KeyManagementDTO keyPair = keyManagementService.generateNewKeyPair(userId, keySize);
            return ResponseEntity.ok(Map.of(
                    "success", true,
                    "message", "Par de chaves gerado com sucesso",
                    "keyPair", keyPair));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of(
                    "success", false,
                    "error", "Erro ao gerar chaves: " + e.getMessage()));
        }
    }

    @Operation(summary = "Obter informações das chaves", description = "Obtém informações das chaves do utilizador")
    @GetMapping("/users/{userId}/keys-info")
    public ResponseEntity<?> getKeysInfo(@PathVariable Long userId) {
        try {
            Map<String, Object> keysInfo = keyManagementService.getKeysInfo(userId);
            return ResponseEntity.ok(Map.of(
                    "success", true,
                    "keys", keysInfo));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of(
                    "success", false,
                    "error", "Erro ao obter informações: " + e.getMessage()));
        }
    }

    @Operation(summary = "Configurar Diffie-Hellman", description = "Configura parâmetros Diffie-Hellman para o utilizador")
    @PostMapping("/users/{userId}/setup-diffie-hellman")
    public ResponseEntity<?> setupDiffieHellman(@PathVariable Long userId) {
        try {
            Map<String, Object> result = keyManagementService.setupDiffieHellman(userId);
            return ResponseEntity.ok(result);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of(
                    "success", false,
                    "error", "Erro ao configurar Diffie-Hellman: " + e.getMessage()));
        }
    }

    @Operation(summary = "Importar chave pública", description = "Importa chave pública no formato PEM")
    @PostMapping("/users/{userId}/import-public-key")
    public ResponseEntity<?> importPublicKey(@PathVariable Long userId, @RequestBody Map<String, String> request) {
        try {
            String pemKey = request.get("pemKey");
            if (pemKey == null) {
                return ResponseEntity.badRequest().body(Map.of(
                        "success", false,
                        "error", "Chave PEM é obrigatória"));
            }

            Map<String, Object> result = keyManagementService.importPublicKey(userId, pemKey);
            return ResponseEntity.ok(result);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of(
                    "success", false,
                    "error", "Erro ao importar chave: " + e.getMessage()));
        }
    }

    @Operation(summary = "Exportar chave pública", description = "Exporta chave pública do utilizador")
    @GetMapping("/users/{userId}/export-public-key")
    public ResponseEntity<?> exportPublicKey(@PathVariable Long userId) {
        try {
            Map<String, Object> exportData = keyManagementService.exportPublicKey(userId);
            return ResponseEntity.ok(Map.of(
                    "success", true,
                    "exportData", exportData));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of(
                    "success", false,
                    "error", "Erro ao exportar chave: " + e.getMessage()));
        }
    }

    @Operation(summary = "Health check")
    @GetMapping("/health")
    public ResponseEntity<?> healthCheck() {
        try {
            return ResponseEntity.ok(Map.of(
                    "status", "UP",
                    "service", "Key Management",
                    "timestamp", java.time.LocalDateTime.now()));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of(
                    "status", "DOWN",
                    "error", e.getMessage()));
        }
    }
}