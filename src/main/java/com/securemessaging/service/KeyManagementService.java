package com.securemessaging.service;

import com.securemessaging.dto.KeyManagementDTO;
import com.securemessaging.model.User;
import com.securemessaging.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.KeyPair;
import java.security.PublicKey;
import java.time.LocalDateTime;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

@Service
public class KeyManagementService {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private CryptoService cryptoService;

    @Autowired
    private UserService userService;

    public KeyManagementDTO generateNewKeyPair(Long userId, int keySize) {
        try {
            User user = userRepository.findById(userId)
                    .orElseThrow(() -> new RuntimeException("Usuário não encontrado"));

            KeyPair keyPair = userService.generateNewRSAKeyPair(userId, keySize);

            String publicKeyStr = user.getPublicKey(); // Já atualizada pelo UserService
            String privateKeyStr = "[ENCRYPTED]"; // Não expor privada descriptografada

            KeyManagementDTO response = new KeyManagementDTO();
            response.setPublicKey(publicKeyStr);
            response.setPrivateKey(privateKeyStr);
            response.setKeyType("RSA");
            response.setKeySize(keySize);

            Map<String, Object> keyInfo = new HashMap<>();
            keyInfo.put("generatedAt", LocalDateTime.now().toString());
            keyInfo.put("algorithm", "RSA");
            keyInfo.put("format", "Base64");
            response.setKeyInfo(keyInfo);

            return response;

        } catch (Exception e) {
            throw new RuntimeException("Erro ao gerar par de chaves: " + e.getMessage(), e);
        }
    }

    public Map<String, Object> getKeysInfo(Long userId) {
        try {
            User user = userRepository.findById(userId)
                    .orElseThrow(() -> new RuntimeException("Usuário não encontrado"));

            Map<String, Object> keysInfo = new HashMap<>();

            // Informações RSA - ✅ USANDO CAMPOS REAIS do User
            Map<String, Object> rsaInfo = new HashMap<>();
            rsaInfo.put("exists", user.getPublicKey() != null && !user.getPublicKey().trim().isEmpty());
            rsaInfo.put("keySize", 1024); // Tamanho padrão do sistema
            rsaInfo.put("algorithm", "RSA");
            rsaInfo.put("created",
                    user.getCreatedAt() != null ? user.getCreatedAt().toString() : LocalDateTime.now().toString());
            rsaInfo.put("publicKeyPresent", user.getPublicKey() != null);
            rsaInfo.put("privateKeyPresent", user.getPrivateKey() != null);

            // Informações Diffie-Hellman - ✅ USANDO CAMPOS REAIS do User
            Map<String, Object> dhInfo = new HashMap<>();
            dhInfo.put("exists", user.getDhPublicKey() != null && !user.getDhPublicKey().trim().isEmpty());
            dhInfo.put("keySize", 1024); // Tamanho padrão para DH
            dhInfo.put("algorithm", "Diffie-Hellman");
            dhInfo.put("created",
                    user.getCreatedAt() != null ? user.getCreatedAt().toString() : LocalDateTime.now().toString());
            dhInfo.put("publicKeyPresent", user.getDhPublicKey() != null);
            dhInfo.put("privateKeyPresent", user.getDhPrivateKey() != null);

            keysInfo.put("rsa", rsaInfo);
            keysInfo.put("dh", dhInfo);

            return keysInfo;

        } catch (Exception e) {
            throw new RuntimeException("Erro ao obter informações das chaves: " + e.getMessage(), e);
        }
    }

    public Map<String, Object> setupDiffieHellman(Long userId) {
        try {
            // ✅ USANDO MÉTODO EXISTENTE do UserService
            userService.setupUserDiffieHellman(userId);

            User user = userRepository.findById(userId)
                    .orElseThrow(() -> new RuntimeException("Usuário não encontrado"));

            Map<String, Object> response = new HashMap<>();
            response.put("success", true);
            response.put("message", "Diffie-Hellman configurado com sucesso");
            response.put("keySize", 1024);
            response.put("publicKey", user.getDhPublicKey() != null ? "Configurada" : "Não configurada");
            return response;

        } catch (Exception e) {
            Map<String, Object> errorResponse = new HashMap<>();
            errorResponse.put("success", false);
            errorResponse.put("message", "Erro ao configurar Diffie-Hellman: " + e.getMessage());
            return errorResponse;
        }
    }

    public Map<String, Object> importPublicKey(Long userId, String pemKey) {
        try {
            User user = userRepository.findById(userId)
                    .orElseThrow(() -> new RuntimeException("Usuário não encontrado"));

            // ✅ VALIDAÇÃO SIMPLES - verificar se parece uma chave Base64
            if (pemKey == null || pemKey.trim().isEmpty()) {
                throw new RuntimeException("Chave não pode estar vazia");
            }

            // Tentar decodificar para verificar se é Base64 válido
            try {
                Base64.getDecoder().decode(pemKey.replaceAll("\\s", ""));
            } catch (IllegalArgumentException e) {
                throw new RuntimeException("Formato de chave inválido - deve ser Base64");
            }

            // ✅ CONVERTER para o formato do sistema (Base64 simples)
            String base64Key = pemKey.replaceAll("-----BEGIN.*?-----", "")
                    .replaceAll("-----END.*?-----", "")
                    .replaceAll("\\s", "");

            // ✅ VALIDAR se é uma chave pública RSA
            try {
                PublicKey publicKey = cryptoService.stringToPublicKey(base64Key);
                if (!"RSA".equals(publicKey.getAlgorithm())) {
                    throw new RuntimeException("Apenas chaves RSA são suportadas");
                }
            } catch (Exception e) {
                throw new RuntimeException("Chave pública inválida: " + e.getMessage());
            }

            user.setPublicKey(base64Key);
            userRepository.save(user);

            Map<String, Object> response = new HashMap<>();
            response.put("success", true);
            response.put("message", "Chave pública importada com sucesso");
            response.put("keyType", "RSA");
            response.put("keySize", 1024);
            return response;

        } catch (Exception e) {
            Map<String, Object> errorResponse = new HashMap<>();
            errorResponse.put("success", false);
            errorResponse.put("message", "Erro ao importar chave: " + e.getMessage());
            return errorResponse;
        }
    }

    public Map<String, Object> exportPublicKey(Long userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("Usuário não encontrado"));

        if (user.getPublicKey() == null || user.getPublicKey().trim().isEmpty()) {
            throw new RuntimeException("Usuário não possui chave pública");
        }

        // ✅ FORMATAR como PEM para exportação
        String pemKey = formatToPEM(user.getPublicKey(), "PUBLIC");

        Map<String, Object> response = new HashMap<>();
        response.put("publicKey", pemKey);
        response.put("format", "PEM");
        response.put("username", user.getUsername());
        response.put("algorithm", "RSA");
        response.put("keySize", 1024);
        response.put("exportedAt", LocalDateTime.now().toString());
        return response;
    }

    // ✅ MÉTODO AUXILIAR - Formatar Base64 como PEM
    private String formatToPEM(String base64Key, String keyType) {
        String header = "-----BEGIN " + keyType + " KEY-----\n";
        String footer = "\n-----END " + keyType + " KEY-----";

        // Quebrar a chave em linhas de 64 caracteres
        StringBuilder formatted = new StringBuilder();
        for (int i = 0; i < base64Key.length(); i += 64) {
            int end = Math.min(i + 64, base64Key.length());
            formatted.append(base64Key.substring(i, end)).append("\n");
        }

        return header + formatted.toString().trim() + footer;
    }

    // ✅ MÉTODO AUXILIAR - Derivar chave AES (já existe no UserService, mas
    // duplicamos aqui para independência)
    private SecretKey deriveAESKeyFromPassword(String password) {
        try {
            String hash = cryptoService.hashWithSHA256(password);
            byte[] keyBytes = hash.getBytes();
            byte[] truncatedKey = new byte[16];
            System.arraycopy(keyBytes, 0, truncatedKey, 0, 16);
            return new SecretKeySpec(truncatedKey, "AES");
        } catch (Exception e) {
            throw new RuntimeException("Erro ao derivar chave AES", e);
        }
    }
}