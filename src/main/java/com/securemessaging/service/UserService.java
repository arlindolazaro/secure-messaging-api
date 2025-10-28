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
    private com.securemessaging.repository.KeyPairRepository keyPairRepository;

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
            // ✅ RSA 1024 bits (requisito I.a)
            KeyPair rsaKeyPair = cryptoService.generateRSAKeyPair(1024);

            // ✅ CORREÇÃO: Usar formato PEM consistentemente
            String publicKeyStr = cryptoService.publicKeyToPEM(rsaKeyPair.getPublic());
            String privateKeyStr = cryptoService.privateKeyToPEM(rsaKeyPair.getPrivate());

            // ✅ Certificado autoassinado (requisito II.a)
            var cert = cryptoService.generateCertificate(rsaKeyPair,
                    "CN=" + user.getUsername(), "OU=Users",
                    "O=Secure Messaging", "L=City", "ST=State", "C=MZ", 365);
            String certBase64 = Base64.getEncoder().encodeToString(cert.getEncoded());

            // ✅ Diffie-Hellman com PRNG 128 bits (requisito I.d)
            KeyPair dhKeyPair = cryptoService.generateDHKeyPair();
            String dhPublicKey = cryptoService.publicKeyToPEM(dhKeyPair.getPublic());
            String dhPrivateKey = cryptoService.privateKeyToPEM(dhKeyPair.getPrivate());

            user.setPublicKey(publicKeyStr);
            user.setPrivateKey(privateKeyStr);
            user.setCertificate(certBase64);
            user.setDhPublicKey(dhPublicKey);
            user.setDhPrivateKey(dhPrivateKey);
            user.setDhPrimeModulus("23");
            user.setDhGenerator("5");
            user.setEnabled(true);
            user.setCreatedAt(LocalDateTime.now());

            // Primeiro persiste o usuário, então persiste o KeyPair referenciando o usuário
            // persistido
            User savedUser = userRepository.save(user);

            // Persist KeyPair entity for this RSA key (signature/encryption)
            com.securemessaging.model.KeyPair kp = new com.securemessaging.model.KeyPair();
            kp.setUser(savedUser);
            kp.setPublicKey(publicKeyStr);
            kp.setPrivateKey(privateKeyStr);
            kp.setAlgorithm("RSA");
            kp.setKeySize(1024);
            kp.setKeyType(com.securemessaging.model.KeyPair.KeyType.ENCRYPTION);
            kp.setActive(true);
            keyPairRepository.save(kp);

            // Manter grafo consistente em memória
            savedUser.getKeyPairs().add(kp);
            // Atualiza usuário para garantir que a coleção esteja sincronizada
            userRepository.save(savedUser);

            // Retorna o usuário persistido
            return savedUser;

        } catch (Exception e) {
            throw new RuntimeException("Falha ao gerar chaves de criptografia: " + e.getMessage(), e);
        }
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

        // ✅ CORREÇÃO: Usar formato PEM
        String newPublicKey = cryptoService.publicKeyToPEM(newKeyPair.getPublic());
        String newPrivateKey = cryptoService.privateKeyToPEM(newKeyPair.getPrivate());

        var cert = cryptoService.generateCertificate(newKeyPair, "CN=" + user.getUsername(), "OU=Users",
                "O=Secure Messaging", "L=City", "ST=State", "C=MZ", 365);
        String certBase64 = Base64.getEncoder().encodeToString(cert.getEncoded());

        user.setCertificate(certBase64);
        user.setPublicKey(newPublicKey);
        user.setPrivateKey(newPrivateKey);

        userRepository.save(user);

        // Persist KeyPair entity
        com.securemessaging.model.KeyPair kp = new com.securemessaging.model.KeyPair();
        kp.setUser(user);
        kp.setPublicKey(newPublicKey);
        kp.setPrivateKey(newPrivateKey);
        kp.setAlgorithm("RSA");
        kp.setKeySize(keySize);
        kp.setKeyType(com.securemessaging.model.KeyPair.KeyType.ENCRYPTION);
        kp.setActive(true);
        keyPairRepository.save(kp);
        return newKeyPair;
    }

    public void setupUserDiffieHellman(Long userId) throws Exception {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("Usuário não encontrado"));

        KeyPair dhKeyPair = cryptoService.generateDHKeyPair();

        // ✅ CORREÇÃO: Usar formato PEM
        String dhPublicKey = cryptoService.publicKeyToPEM(dhKeyPair.getPublic());
        String dhPrivateKey = cryptoService.privateKeyToPEM(dhKeyPair.getPrivate());

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

        // ✅ CORREÇÃO: Extrair Base64 do PEM para processamento
        String user1DhPublicKeyBase64 = cryptoService.extractBase64FromPEM(user1.getDhPublicKey());
        String user2DhPublicKeyBase64 = cryptoService.extractBase64FromPEM(user2.getDhPublicKey());

        byte[] user1PublicKeyBytes = Base64.getDecoder().decode(user1DhPublicKeyBase64);
        byte[] user2PublicKeyBytes = Base64.getDecoder().decode(user2DhPublicKeyBase64);

        KeyFactory keyFactory = KeyFactory.getInstance("DH");
        PublicKey user1PublicKey = keyFactory.generatePublic(new X509EncodedKeySpec(user1PublicKeyBytes));
        PublicKey user2PublicKey = keyFactory.generatePublic(new X509EncodedKeySpec(user2PublicKeyBytes));

        // Extrair Base64 das chaves privadas PEM
        String user1DhPrivateKeyBase64 = cryptoService.extractBase64FromPEM(user1.getDhPrivateKey());
        String user2DhPrivateKeyBase64 = cryptoService.extractBase64FromPEM(user2.getDhPrivateKey());

        PrivateKey user1PrivateKey = cryptoService.stringToPrivateKey(user1DhPrivateKeyBase64, "DH");
        PrivateKey user2PrivateKey = cryptoService.stringToPrivateKey(user2DhPrivateKeyBase64, "DH");

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

        // ✅ Garantir que retorna PEM (já está armazenado como PEM)
        return user.getPublicKey();
    }

    public String getUserDHPublicKey(Long userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("Usuário não encontrado"));

        if (user.getDhPublicKey() == null) {
            throw new RuntimeException("Usuário não possui chave pública DH");
        }

        // ✅ Garantir que retorna PEM (já está armazenado como PEM)
        return user.getDhPublicKey();
    }

    public Map<String, Object> exportUserKeys(Long userId, String password) throws Exception {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("Usuário não encontrado"));

        if (!passwordEncoder.matches(password, user.getPassword())) {
            throw new SecurityException("Password incorreta");
        }

        Map<String, Object> keys = new HashMap<>();
        keys.put("publicKey", user.getPublicKey()); // ✅ Já em PEM
        keys.put("privateKey", user.getPrivateKey()); // ✅ Já em PEM
        keys.put("dhPublicKey", user.getDhPublicKey()); // ✅ Já em PEM
        keys.put("dhPrivateKey", user.getDhPrivateKey()); // ✅ Já em PEM
        keys.put("certificate", user.getCertificate());
        keys.put("exportedAt", LocalDateTime.now());
        keys.put("username", user.getUsername());
        keys.put("keyFormat", "PEM");
        keys.put("rsaKeySize", 1024);

        return keys;
    }

    // ==================== ESTATÍSTICAS ====================

    public Map<String, Object> getUserStatistics(Long userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("Usuário não encontrado"));

        try {
            long sentMessageCount = messageRepository.countBySenderId(userId);
            long receivedMessageCount = messageRepository.countByReceiverId(userId);
            long textMessageCount = messageRepository.countBySenderIdAndMessageType(userId, Message.MessageType.TEXT);
            long imageMessageCount = messageRepository.countBySenderIdAndMessageType(userId, Message.MessageType.IMAGE);
            long encryptedSentMessageCount = messageRepository.countBySenderIdAndEncrypted(userId, true);
            long normalSentMessageCount = messageRepository.countBySenderIdAndEncrypted(userId, false);
            long encryptedReceivedMessageCount = messageRepository.countByReceiverIdAndEncrypted(userId, true);
            long normalReceivedMessageCount = messageRepository.countByReceiverIdAndEncrypted(userId, false);

            Map<String, Object> stats = new HashMap<>();

            // 🟢 INFORMAÇÕES BÁSICAS
            stats.put("userId", userId);
            stats.put("username", user.getUsername());
            stats.put("email", user.getEmail());
            stats.put("hasPublicKey", user.getPublicKey() != null);
            stats.put("hasDhKeys", user.getDhPublicKey() != null);
            // Usar a coleção de certificados para contar corretamente
            stats.put("certificateCount", user.getCertificates() != null ? user.getCertificates().size() : 0);
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

            return stats;

        } catch (Exception e) {
            System.err.println("❌ Erro ao carregar estatísticas: " + e.getMessage());
            return createFallbackStatistics(user);
        }
    }

    // ==================== USER SETTINGS ====================

    public String getUserSettings(Long userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("Usuário não encontrado"));
        return user.getUserSettings();
    }

    public void updateUserSettings(Long userId, String settingsJson) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("Usuário não encontrado"));
        user.setUserSettings(settingsJson);
        userRepository.save(user);
    }

    // ==================== REMOVER UTILIZADOR ====================
    public void deleteUser(Long userId) {
        // Em produção, validar permissões (apenas admin ou o próprio utilizador)
        if (!userRepository.existsById(userId)) {
            throw new RuntimeException("Usuário não encontrado");
        }
        userRepository.deleteById(userId);
    }

    private Map<String, Object> createFallbackStatistics(User user) {
        Map<String, Object> fallbackStats = new HashMap<>();
        fallbackStats.put("userId", user.getId());
        fallbackStats.put("username", user.getUsername());
        fallbackStats.put("email", user.getEmail());
        fallbackStats.put("hasPublicKey", user.getPublicKey() != null);
        fallbackStats.put("hasDhKeys", user.getDhPublicKey() != null);
        fallbackStats.put("certificateCount", user.getCertificates() != null ? user.getCertificates().size() : 0);
        fallbackStats.put("keyPairCount", 1);
        fallbackStats.put("createdAt", user.getCreatedAt());
        fallbackStats.put("lastLogin", user.getLastLogin());
        fallbackStats.put("enabled", user.isEnabled());
        fallbackStats.putAll(getDefaultMessageStats());
        fallbackStats.put("fallback", true);

        return fallbackStats;
    }

    private Map<String, Object> getDefaultMessageStats() {
        Map<String, Object> defaultStats = new HashMap<>();
        defaultStats.put("sentMessageCount", 0);
        defaultStats.put("receivedMessageCount", 0);
        defaultStats.put("totalMessageCount", 0);
        defaultStats.put("textMessageCount", 0);
        defaultStats.put("imageMessageCount", 0);
        defaultStats.put("encryptedMessageCount", 0);
        defaultStats.put("normalMessageCount", 0);
        defaultStats.put("encryptedReceivedMessageCount", 0);
        defaultStats.put("normalReceivedMessageCount", 0);
        defaultStats.put("messageEncryptionRate", 0);
        defaultStats.put("activityLevel", "Iniciante");
        defaultStats.put("engagementRate", "0%");
        return defaultStats;
    }

    private String calculateActivityLevel(long sentMessageCount) {
        if (sentMessageCount == 0)
            return "Iniciante";
        if (sentMessageCount < 10)
            return "Ocasional";
        if (sentMessageCount < 50)
            return "activo";
        if (sentMessageCount < 100)
            return "Muito activo";
        return "Super activo";
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

    private UserDTO convertToDTO(User user) {
        UserDTO dto = new UserDTO();
        dto.setId(user.getId());
        dto.setUsername(user.getUsername());
        dto.setEmail(user.getEmail());
        dto.setPublicKey(user.getPublicKey()); // ✅ Já em PEM
        dto.setDhPublicKey(user.getDhPublicKey()); // ✅ Já em PEM
        dto.setCertificate(user.getCertificate());
        dto.setEnabled(user.isEnabled());
        dto.setCreatedAt(user.getCreatedAt());
        dto.setLastLogin(user.getLastLogin());
        // Preencher contadores para exibir estatísticas no frontend
        dto.setCertificateCount(user.getCertificates() != null ? user.getCertificates().size() : 0);
        int keyPairs = 0;
        if (user.getPublicKey() != null && user.getPrivateKey() != null)
            keyPairs = 1;
        dto.setKeyPairCount(keyPairs);
        // Mensagens serão agregadas por endpoints específicos; deixar 0 como padrão
        // aqui
        dto.setSentMessageCount(0);
        dto.setReceivedMessageCount(0);
        return dto;
    }

    public UserDTO convertToDetailedDTO(User user) {
        return convertToDTO(user);
    }
}