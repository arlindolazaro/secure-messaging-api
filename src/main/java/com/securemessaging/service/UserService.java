package com.securemessaging.service;

import com.securemessaging.dto.UserDTO;
import com.securemessaging.model.Message;
import com.securemessaging.model.User;
import com.securemessaging.repository.MessageRepository;
import com.securemessaging.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.time.LocalDateTime;
import java.util.*;
import java.util.stream.Collectors;

@Service
@Transactional
public class UserService {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private MessageRepository messageRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private CryptoService cryptoService;

    @Autowired
    private DiffieHellmanService diffieHellmanService;

    // ==================== REGISTO E GESTÃO DE CHAVES ====================

    public User createUser(User user) {
        if (userRepository.existsByUsername(user.getUsername())) {
            throw new RuntimeException("Username já existe");
        }
        if (userRepository.existsByEmail(user.getEmail())) {
            throw new RuntimeException("Email já cadastrado");
        }

        String encodedPassword = passwordEncoder.encode(user.getPassword());
        user.setPassword(encodedPassword);

        try {
            KeyPair rsaKeyPair = cryptoService.generateRSAKeyPair(1024);
            String publicKeyStr = Base64.getEncoder().encodeToString(rsaKeyPair.getPublic().getEncoded());
            String privateKeyStr = Base64.getEncoder().encodeToString(rsaKeyPair.getPrivate().getEncoded());

            var cert = cryptoService.generateCertificate(rsaKeyPair, "CN=" + user.getUsername(), "OU=Users",
                    "O=Secure Messaging", "L=City", "ST=State", "C=US", 365);
            String certBase64 = Base64.getEncoder().encodeToString(cert.getEncoded());

            KeyPair dhKeyPair = cryptoService.generateDHKeyPair();
            String dhPublicKey = Base64.getEncoder().encodeToString(dhKeyPair.getPublic().getEncoded());
            String dhPrivateKey = Base64.getEncoder().encodeToString(dhKeyPair.getPrivate().getEncoded());

            user.setPublicKey(publicKeyStr);
            user.setPrivateKey(privateKeyStr);
            user.setCertificate(certBase64);
            user.setDhPublicKey(dhPublicKey);
            user.setDhPrivateKey(dhPrivateKey);
            user.setDhPrimeModulus("23");
            user.setDhGenerator("5");
            user.setEnabled(true);
            user.setCreatedAt(LocalDateTime.now());

        } catch (Exception e) {
            throw new RuntimeException("Falha ao gerar chaves de criptografia: " + e.getMessage(), e);
        }

        return userRepository.save(user);
    }

    public PrivateKey getPrivateKey(Long userId) throws Exception {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("Usuário não encontrado"));

        if (user.getPrivateKey() == null) {
            throw new RuntimeException("Usuário não possui chave privada");
        }

        return cryptoService.stringToPrivateKey(user.getPrivateKey());
    }

    public PrivateKey getDecryptedPrivateKey(Long userId, String password) throws Exception {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("Usuário não encontrado"));

        if (user.getPrivateKey() == null) {
            throw new RuntimeException("Usuário não possui chave privada");
        }

        if (!passwordEncoder.matches(password, user.getPassword())) {
            throw new SecurityException("Password incorreta");
        }

        return cryptoService.stringToPrivateKey(user.getPrivateKey());
    }

    // ==================== GESTÃO DE CHAVES ====================

    public KeyPair generateNewRSAKeyPair(Long userId, int keySize) throws Exception {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("Usuário não encontrado"));

        KeyPair newKeyPair = cryptoService.generateRSAKeyPair(keySize);
        String newPublicKey = Base64.getEncoder().encodeToString(newKeyPair.getPublic().getEncoded());
        String newPrivateKey = Base64.getEncoder().encodeToString(newKeyPair.getPrivate().getEncoded());

        var cert = cryptoService.generateCertificate(newKeyPair, "CN=" + user.getUsername(), "OU=Users",
                "O=Secure Messaging", "L=City", "ST=State", "C=US", 365);
        String certBase64 = Base64.getEncoder().encodeToString(cert.getEncoded());
        user.setCertificate(certBase64);

        user.setPublicKey(newPublicKey);
        user.setPrivateKey(newPrivateKey);

        userRepository.save(user);
        return newKeyPair;
    }

    public void setupUserDiffieHellman(Long userId) throws Exception {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("Usuário não encontrado"));

        KeyPair dhKeyPair = cryptoService.generateDHKeyPair();
        String dhPublicKey = Base64.getEncoder().encodeToString(dhKeyPair.getPublic().getEncoded());
        String dhPrivateKey = Base64.getEncoder().encodeToString(dhKeyPair.getPrivate().getEncoded());

        user.setDhPublicKey(dhPublicKey);
        user.setDhPrivateKey(dhPrivateKey);
        user.setDhPrimeModulus("23");
        user.setDhGenerator("5");

        userRepository.save(user);
    }

    public Map<String, Object> performDiffieHellmanKeyExchange(Long userId1, Long userId2) throws Exception {
        User user1 = userRepository.findById(userId1)
                .orElseThrow(() -> new RuntimeException("Usuário 1 não encontrado"));
        User user2 = userRepository.findById(userId2)
                .orElseThrow(() -> new RuntimeException("Usuário 2 não encontrado"));

        if (user1.getDhPublicKey() == null || user2.getDhPublicKey() == null) {
            throw new RuntimeException("Um ou ambos os usuários não possuem chaves DH configuradas");
        }

        byte[] user1PublicKeyBytes = Base64.getDecoder().decode(user1.getDhPublicKey());
        byte[] user2PublicKeyBytes = Base64.getDecoder().decode(user2.getDhPublicKey());

        KeyFactory keyFactory = KeyFactory.getInstance("DH");
        PublicKey user1PublicKey = keyFactory.generatePublic(new X509EncodedKeySpec(user1PublicKeyBytes));
        PublicKey user2PublicKey = keyFactory.generatePublic(new X509EncodedKeySpec(user2PublicKeyBytes));

        // DH private keys are PKCS#8 encoded but use the DH algorithm; use the
        // overload that accepts the algorithm to parse correctly.
        PrivateKey user1PrivateKey = cryptoService.stringToPrivateKey(user1.getDhPrivateKey(), "DH");
        PrivateKey user2PrivateKey = cryptoService.stringToPrivateKey(user2.getDhPrivateKey(), "DH");

        byte[] sharedSecret1 = cryptoService.generateDHSharedSecret(user1PrivateKey, user2PublicKey);
        byte[] sharedSecret2 = cryptoService.generateDHSharedSecret(user2PrivateKey, user1PublicKey);

        boolean secretsMatch = Arrays.equals(sharedSecret1, sharedSecret2);

        SecretKey aesKey1 = cryptoService.deriveAESKeyFromDHSecret(sharedSecret1);
        SecretKey aesKey2 = cryptoService.deriveAESKeyFromDHSecret(sharedSecret2);

        Map<String, Object> result = new HashMap<>();
        result.put("success", secretsMatch);
        result.put("secretsMatch", secretsMatch);
        result.put("sharedSecretUser1", Base64.getEncoder().encodeToString(sharedSecret1));
        result.put("sharedSecretUser2", Base64.getEncoder().encodeToString(sharedSecret2));
        result.put("aesKeyUser1", Base64.getEncoder().encodeToString(aesKey1.getEncoded()));
        result.put("aesKeyUser2", Base64.getEncoder().encodeToString(aesKey2.getEncoded()));
        result.put("keyAlgorithm", "AES");
        result.put("keySize", 128);
        result.put("exchangeTime", LocalDateTime.now());

        return result;
    }

    // ==================== AUTENTICAÇÃO E SENHA ====================

    public boolean verifyPassword(Long userId, String plainPassword) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("Usuário não encontrado"));

        return passwordEncoder.matches(plainPassword, user.getPassword());
    }

    public void updatePassword(Long userId, String newPassword) throws Exception {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("Usuário não encontrado"));

        String encodedNewPassword = passwordEncoder.encode(newPassword);
        user.setPassword(encodedNewPassword);
        userRepository.save(user);
    }

    // ==================== CONSULTAS ====================

    public Optional<User> findByUsername(String username) {
        return userRepository.findByUsername(username);
    }

    public Optional<User> findByEmail(String email) {
        return userRepository.findByEmail(email);
    }

    public Optional<User> findById(Long id) {
        return userRepository.findById(id);
    }

    public boolean existsByUsername(String username) {
        return userRepository.existsByUsername(username);
    }

    public boolean existsByEmail(String email) {
        return userRepository.existsByEmail(email);
    }

    public List<UserDTO> getAllUsers() {
        return userRepository.findAll().stream()
                .map(this::convertToDTO)
                .collect(Collectors.toList());
    }

    public List<UserDTO> getActiveUsers() {
        return userRepository.findActiveUsers().stream()
                .map(this::convertToDTO)
                .collect(Collectors.toList());
    }

    public List<UserDTO> getUsersWithPublicKey() {
        return userRepository.findUsersWithPublicKey().stream()
                .map(this::convertToDTO)
                .collect(Collectors.toList());
    }

    // ==================== GESTÃO DE ESTADO ====================

    public void enableUser(Long userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("Usuário não encontrado"));
        user.setEnabled(true);
        userRepository.save(user);
    }

    public void disableUser(Long userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("Usuário não encontrado"));
        user.setEnabled(false);
        userRepository.save(user);
    }

    public void updateLastLogin(Long userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("Usuário não encontrado"));
        user.setLastLogin(LocalDateTime.now());
        userRepository.save(user);
    }

    // ==================== SEGURANÇA E CHAVES ====================

    public String getUserPublicKey(Long userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("Usuário não encontrado"));

        if (user.getPublicKey() == null) {
            throw new RuntimeException("Usuário não possui chave pública");
        }

        return user.getPublicKey();
    }

    public String getUserDHPublicKey(Long userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("Usuário não encontrado"));

        if (user.getDhPublicKey() == null) {
            throw new RuntimeException("Usuário não possui chave pública DH");
        }

        return user.getDhPublicKey();
    }

    public Map<String, Object> exportUserKeys(Long userId, String password) throws Exception {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("Usuário não encontrado"));

        if (!passwordEncoder.matches(password, user.getPassword())) {
            throw new SecurityException("Password incorreta");
        }

        Map<String, Object> keys = new HashMap<>();
        keys.put("publicKey", user.getPublicKey());
        keys.put("privateKey", user.getPrivateKey());
        keys.put("dhPublicKey", user.getDhPublicKey());
        keys.put("dhPrivateKey", user.getDhPrivateKey());
        keys.put("certificate", user.getCertificate());
        keys.put("exportedAt", LocalDateTime.now());
        keys.put("username", user.getUsername());

        return keys;
    }

    // ==================== ESTATÍSTICAS ====================

    public Map<String, Object> getUserStatistics(Long userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("Usuário não encontrado"));

        try {
            // ✅ USAR OS MÉTODOS CORRETOS DO REPOSITORY
            long sentMessageCount = messageRepository.countBySenderId(userId);
            long receivedMessageCount = messageRepository.countByReceiverId(userId);
            long textMessageCount = messageRepository.countBySenderIdAndMessageType(userId, Message.MessageType.TEXT);
            long imageMessageCount = messageRepository.countBySenderIdAndMessageType(userId, Message.MessageType.IMAGE);
            long encryptedSentMessageCount = messageRepository.countBySenderIdAndEncrypted(userId, true);
            long normalSentMessageCount = messageRepository.countBySenderIdAndEncrypted(userId, false);

            // ✅ ESTATÍSTICAS DE MENSAGENS RECEBIDAS
            long encryptedReceivedMessageCount = messageRepository.countByReceiverIdAndEncrypted(userId, true);
            long normalReceivedMessageCount = messageRepository.countByReceiverIdAndEncrypted(userId, false);

            Map<String, Object> stats = new HashMap<>();

            // 🟢 INFORMAÇÕES BÁSICAS
            stats.put("userId", userId);
            stats.put("username", user.getUsername());
            stats.put("email", user.getEmail());
            stats.put("hasPublicKey", user.getPublicKey() != null);
            stats.put("hasDhKeys", user.getDhPublicKey() != null);
            stats.put("certificateCount", user.getCertificate() != null ? 1 : 0);
            stats.put("keyPairCount", 1);
            stats.put("createdAt", user.getCreatedAt());
            stats.put("lastLogin", user.getLastLogin());
            stats.put("enabled", user.isEnabled());

            // 🟢 ESTATÍSTICAS DE MENSAGENS
            stats.put("sentMessageCount", sentMessageCount);
            stats.put("receivedMessageCount", receivedMessageCount);
            stats.put("totalMessageCount", sentMessageCount + receivedMessageCount);
            stats.put("textMessageCount", textMessageCount);
            stats.put("imageMessageCount", imageMessageCount);
            stats.put("encryptedMessageCount", encryptedSentMessageCount);
            stats.put("normalMessageCount", normalSentMessageCount);
            stats.put("encryptedReceivedMessageCount", encryptedReceivedMessageCount);
            stats.put("normalReceivedMessageCount", normalReceivedMessageCount);

            // 🟢 TAXAS E NÍVEIS
            stats.put("messageEncryptionRate",
                    sentMessageCount > 0 ? (double) encryptedSentMessageCount / sentMessageCount * 100 : 0);
            stats.put("activityLevel", calculateActivityLevel(sentMessageCount));
            stats.put("engagementRate", calculateEngagementRate(sentMessageCount, receivedMessageCount));

            System.out.println("📊 Estatísticas carregadas para usuário " + userId + ": " + stats);

            return stats;

        } catch (Exception e) {
            System.err.println("❌ Erro ao carregar estatísticas: " + e.getMessage());

            // ✅ FALLBACK EM CASO DE ERRO
            return createFallbackStatistics(user);
        }
    }

    private Map<String, Object> createFallbackStatistics(User user) {
        Map<String, Object> fallbackStats = new HashMap<>();
        fallbackStats.put("userId", user.getId());
        fallbackStats.put("username", user.getUsername());
        fallbackStats.put("email", user.getEmail());
        fallbackStats.put("hasPublicKey", user.getPublicKey() != null);
        fallbackStats.put("hasDhKeys", user.getDhPublicKey() != null);
        fallbackStats.put("certificateCount", user.getCertificate() != null ? 1 : 0);
        fallbackStats.put("keyPairCount", 1);
        fallbackStats.put("createdAt", user.getCreatedAt());
        fallbackStats.put("lastLogin", user.getLastLogin());
        fallbackStats.put("enabled", user.isEnabled());
        fallbackStats.put("sentMessageCount", 0);
        fallbackStats.put("receivedMessageCount", 0);
        fallbackStats.put("totalMessageCount", 0);
        fallbackStats.put("textMessageCount", 0);
        fallbackStats.put("imageMessageCount", 0);
        fallbackStats.put("encryptedMessageCount", 0);
        fallbackStats.put("normalMessageCount", 0);
        fallbackStats.put("messageEncryptionRate", 0);
        fallbackStats.put("activityLevel", "Iniciante");
        fallbackStats.put("engagementRate", "0%");
        fallbackStats.put("fallback", true);

        return fallbackStats;
    }

    private String calculateActivityLevel(long sentMessageCount) {
        if (sentMessageCount == 0)
            return "Iniciante";
        if (sentMessageCount < 10)
            return "Ocasional";
        if (sentMessageCount < 50)
            return "Ativo";
        if (sentMessageCount < 100)
            return "Muito Ativo";
        return "Super Ativo";
    }

    private String calculateEngagementRate(long sent, long received) {
        if (sent + received == 0)
            return "0%";
        double rate = (double) sent / (sent + received) * 100;
        return Math.round(rate) + "%";
    }

    public long getTotalUserCount() {
        return userRepository.count();
    }

    public long getActiveUserCount() {
        return userRepository.countActiveUsers();
    }

    // ==================== MÉTODOS AUXILIARES ====================

    private SecretKey deriveAESKeyFromPassword(String password) {
        try {
            java.security.MessageDigest md = java.security.MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(password.getBytes("UTF-8"));
            byte[] aesKeyBytes = new byte[16];
            System.arraycopy(digest, 0, aesKeyBytes, 0, 16);
            return new SecretKeySpec(aesKeyBytes, "AES");
        } catch (Exception e) {
            throw new RuntimeException("Erro ao derivar chave AES: " + e.getMessage(), e);
        }
    }

    private UserDTO convertToDTO(User user) {
        UserDTO dto = new UserDTO();
        dto.setId(user.getId());
        dto.setUsername(user.getUsername());
        dto.setEmail(user.getEmail());
        dto.setPublicKey(user.getPublicKey());
        dto.setDhPublicKey(user.getDhPublicKey());
        dto.setCertificate(user.getCertificate());
        dto.setEnabled(user.isEnabled());
        dto.setCreatedAt(user.getCreatedAt());
        dto.setLastLogin(user.getLastLogin());
        return dto;
    }

    public UserDTO convertToDetailedDTO(User user) {
        UserDTO dto = convertToDTO(user);
        return dto;
    }
}