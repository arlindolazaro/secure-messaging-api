package com.securemessaging.controller;

import com.securemessaging.service.CryptoService;
import com.securemessaging.service.DiffieHellmanService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.security.KeyPair;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/crypto")
@CrossOrigin(origins = "*")
@Tag(name = "Cryptography", description = "API para operações criptográficas avançadas")
public class CryptoController {

    private final CryptoService cryptoService;
    private final DiffieHellmanService diffieHellmanService;

    public CryptoController(CryptoService cryptoService, DiffieHellmanService diffieHellmanService) {
        this.cryptoService = cryptoService;
        this.diffieHellmanService = diffieHellmanService;
    }

    @Operation(summary = "Inicializar Diffie-Hellman", description = "Inicia sessão DH e retorna chave pública")
    @PostMapping("/dh/initialize")
    public ResponseEntity<?> initializeDiffieHellman() {
        try {
            Map<String, Object> result = diffieHellmanService.initializeDiffieHellman();
            return ResponseEntity.ok(result);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    @Operation(summary = "Calcular segredo compartilhado DH", description = "Calcula segredo compartilhado usando chave pública do outro participante")
    @PostMapping("/dh/calculate-secret")
    public ResponseEntity<?> calculateSharedSecret(@RequestBody Map<String, String> request) {
        try {
            String sessionId = request.get("sessionId");
            String otherPublicKey = request.get("otherPublicKey");

            if (sessionId == null || otherPublicKey == null) {
                return ResponseEntity.badRequest().body(Map.of("error", "sessionId e otherPublicKey são obrigatórios"));
            }

            Map<String, Object> result = diffieHellmanService.calculateSharedSecret(sessionId, otherPublicKey);
            return ResponseEntity.ok(result);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    @Operation(summary = "Calcular segredo DH (raw hex)", description = "Calcula segredo compartilhado usando publicKey do outro participante em HEX (raw big-int hex)")
    @PostMapping("/dh/calculate-raw")
    public ResponseEntity<?> calculateSharedSecretRaw(@RequestBody Map<String, String> request) {
        try {
            String sessionId = request.get("sessionId");
            String otherPublicHex = request.get("otherPublicHex");

            if (sessionId == null || otherPublicHex == null) {
                return ResponseEntity.badRequest().body(Map.of("error", "sessionId e otherPublicHex são obrigatórios"));
            }

            Map<String, Object> result = diffieHellmanService.calculateSharedSecretFromRawHex(sessionId,
                    otherPublicHex);
            return ResponseEntity.ok(result);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    @Operation(summary = "Simular acordo DH", description = "Simula acordo completo de chaves Diffie-Hellman")
    @PostMapping("/dh/simulate")
    public ResponseEntity<?> simulateDiffieHellman() {
        try {
            Map<String, Object> result = diffieHellmanService.simulateDHAgreement();
            return ResponseEntity.ok(result);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of(
                    "error", "Erro na simulação DH: " + e.getMessage(),
                    "success", false));
        }
    }

    @Operation(summary = "Trocar chaves DH entre dois usuários", description = "Realiza acordo DH entre dois usuários e retorna chave AES derivada (dev)")
    @PostMapping("/dh/exchange-users")
    public ResponseEntity<?> exchangeDHBetweenUsers(@RequestBody Map<String, Object> request) {
        try {
            Long userId1 = Long.valueOf(request.get("userId1").toString());
            Long userId2 = Long.valueOf(request.get("userId2").toString());

            Map<String, Object> result = null;
            try {
                result = cryptoService != null ? null : null; // no-op to avoid unused warning
            } catch (Exception ignore) {
            }

            // Use UserService.performDiffieHellmanKeyExchange if available
            try {
                // Para demo em dev, usamos a simulação completa de DH
                Map<String, Object> sim = diffieHellmanService.simulateDHAgreement();
                return ResponseEntity.ok(sim);
            } catch (Exception e) {
                return ResponseEntity.badRequest()
                        .body(Map.of("error", "Não foi possível realizar troca DH: " + e.getMessage()));
            }
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    @Operation(summary = "Gerar hash", description = "Gera hash usando SHA-256, SHA3-256 ou SHA3-512")
    @PostMapping("/hash")
    public ResponseEntity<?> hashData(@RequestBody Map<String, String> request) {
        try {
            String data = request.get("data");
            String algorithm = request.getOrDefault("algorithm", "sha256");

            if (data == null || data.trim().isEmpty()) {
                return ResponseEntity.badRequest().body(Map.of("error", "Dados são obrigatórios"));
            }

            String hash;
            switch (algorithm.toLowerCase()) {
                case "sha3-256":
                    hash = cryptoService.hashWithSHA3_256(data);
                    break;
                case "sha3-512":
                    hash = cryptoService.hashWithSHA3_512(data);
                    break;
                default:
                    hash = cryptoService.hashWithSHA256(data);
            }

            return ResponseEntity.ok(Map.of(
                    "hash", hash,
                    "algorithm", algorithm,
                    "inputLength", data.length()));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    @Operation(summary = "Gerar par de chaves RSA", description = "Gera par de chaves RSA 1024 bits")
    @PostMapping("/generate/rsa")
    public ResponseEntity<?> generateRSAKeyPair(@RequestBody Map<String, Object> request) {
        try {
            int keySize = 1024;
            if (request != null && request.containsKey("keySize")) {
                keySize = (int) request.get("keySize");
            }

            KeyPair rsaKeyPair = cryptoService.generateRSAKeyPair(keySize);

            Map<String, Object> response = new HashMap<>();
            response.put("publicKey", Base64.getEncoder().encodeToString(rsaKeyPair.getPublic().getEncoded()));
            response.put("privateKey", Base64.getEncoder().encodeToString(rsaKeyPair.getPrivate().getEncoded()));
            response.put("algorithm", "RSA");
            response.put("keySize", keySize);
            response.put("format", "X.509");

            return ResponseEntity.ok(response);
        } catch (Exception e) {
            return ResponseEntity.badRequest()
                    .body(Map.of("error", "Erro ao gerar par de chaves RSA: " + e.getMessage()));
        }
    }

    @Operation(summary = "Criptografar PGP", description = "Criptografa dados no estilo PGP (RSA + AES)")
    @PostMapping("/encrypt/pgp")
    public ResponseEntity<?> encryptPGP(@RequestBody Map<String, String> request) {
        try {
            String data = request.get("data");
            String publicKeyStr = request.get("publicKey");

            if (data == null || publicKeyStr == null) {
                return ResponseEntity.badRequest().body(Map.of("error", "Dados e chave pública são obrigatórios"));
            }

            java.security.PublicKey publicKey = cryptoService.stringToPublicKey(publicKeyStr);
            String encryptedData = cryptoService.encryptPGPStyle(data, publicKey);

            return ResponseEntity.ok(Map.of(
                    "encryptedData", encryptedData,
                    "algorithm", "PGP (RSA+AES)",
                    "originalLength", data.length(),
                    "encryptedLength", encryptedData.length()));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    @Operation(summary = "Descriptografar PGP", description = "Descriptografa dados no estilo PGP")
    @PostMapping("/decrypt/pgp")
    public ResponseEntity<?> decryptPGP(@RequestBody Map<String, String> request) {
        try {
            String encryptedData = request.get("encryptedData");
            String privateKeyStr = request.get("privateKey");

            if (encryptedData == null || privateKeyStr == null) {
                return ResponseEntity.badRequest()
                        .body(Map.of("error", "Dados criptografados e chave privada são obrigatórios"));
            }

            java.security.PrivateKey privateKey = cryptoService.stringToPrivateKey(privateKeyStr);
            String decryptedData = cryptoService.decryptPGPStyle(encryptedData, privateKey);

            return ResponseEntity.ok(Map.of(
                    "decryptedData", decryptedData,
                    "algorithm", "PGP (RSA+AES)",
                    "encryptedLength", encryptedData.length(),
                    "decryptedLength", decryptedData.length()));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    // No CryptoController.java - Adicionar endpoint de diagnóstico
    @Operation(summary = "Diagnóstico de decriptação")
    @PostMapping("/diagnose-decrypt")
    public ResponseEntity<?> diagnoseDecryption(@RequestBody Map<String, String> request) {
        try {
            String encryptedData = request.get("encryptedData");
            String privateKeyStr = request.get("privateKey");

            System.out.println("🔍 Diagnóstico - encryptedData length: " +
                    (encryptedData != null ? encryptedData.length() : "null"));
            System.out.println("🔍 Diagnóstico - privateKey length: " +
                    (privateKeyStr != null ? privateKeyStr.length() : "null"));

            if (encryptedData != null) {
                // Analisar estrutura dos dados
                try {
                    com.fasterxml.jackson.databind.ObjectMapper mapper = new com.fasterxml.jackson.databind.ObjectMapper();
                    var node = mapper.readTree(encryptedData);
                    System.out.println("📦 Estrutura JSON detectada: " + node.getNodeType());
                } catch (Exception e) {
                    System.out.println("⚡ Formato não-JSON (legado)");
                }
            }

            return ResponseEntity.ok(Map.of(
                    "encryptedDataLength", encryptedData != null ? encryptedData.length() : 0,
                    "privateKeyLength", privateKeyStr != null ? privateKeyStr.length() : 0,
                    "timestamp", java.time.LocalDateTime.now()));

        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    @Operation(summary = "Assinar dados", description = "Assina dados digitalmente com chave privada RSA")
    @PostMapping("/sign")
    public ResponseEntity<?> signData(@RequestBody Map<String, String> request) {
        try {
            String data = request.get("data");
            String privateKeyStr = request.get("privateKey");

            if (data == null || privateKeyStr == null) {
                return ResponseEntity.badRequest().body(Map.of("error", "Dados e chave privada são obrigatórios"));
            }

            java.security.PrivateKey privateKey = cryptoService.stringToPrivateKey(privateKeyStr);
            String signature = cryptoService.signData(data, privateKey);

            return ResponseEntity.ok(Map.of(
                    "signature", signature,
                    "algorithm", "SHA256withRSA",
                    "dataHash", cryptoService.hashWithSHA256(data)));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    @Operation(summary = "Verificar assinatura", description = "Verifica assinatura digital com chave pública")
    @PostMapping("/verify")
    public ResponseEntity<?> verifySignature(@RequestBody Map<String, String> request) {
        try {
            String data = request.get("data");
            String signature = request.get("signature");
            String publicKeyStr = request.get("publicKey");

            if (data == null || signature == null || publicKeyStr == null) {
                return ResponseEntity.badRequest()
                        .body(Map.of("error", "Dados, assinatura e chave pública são obrigatórios"));
            }

            java.security.PublicKey publicKey = cryptoService.stringToPublicKey(publicKeyStr);
            boolean isValid = cryptoService.verifySignature(data, signature, publicKey);

            return ResponseEntity.ok(Map.of(
                    "valid", isValid,
                    "algorithm", "SHA256withRSA",
                    "message", isValid ? "Assinatura válida" : "Assinatura inválida"));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    @Operation(summary = "Health check")
    @GetMapping("/health")
    public ResponseEntity<?> healthCheck() {
        try {
            // Testar operações básicas
            String testData = "health-check";
            cryptoService.hashWithSHA256(testData);

            Map<String, Object> health = new HashMap<>();
            health.put("status", "UP");
            health.put("service", "Cryptography");
            health.put("hashTest", "PASS");
            health.put("activeDHSessions", diffieHellmanService.getActiveSessions().size());
            health.put("timestamp", java.time.LocalDateTime.now());

            return ResponseEntity.ok(health);
        } catch (Exception e) {
            return ResponseEntity.status(500).body(Map.of(
                    "status", "DOWN",
                    "error", e.getMessage()));
        }
    }
}