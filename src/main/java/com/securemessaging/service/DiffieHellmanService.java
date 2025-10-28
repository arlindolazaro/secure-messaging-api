package com.securemessaging.service;

import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.math.BigInteger;
import java.security.*;
import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.interfaces.DHPublicKey;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.spec.DHParameterSpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

@Service
public class DiffieHellmanService {

    private final CryptoService cryptoService;
    private final Map<String, KeyPair> dhSessions = new HashMap<>();
    private final Map<String, byte[]> sharedSecrets = new HashMap<>();

    public DiffieHellmanService(CryptoService cryptoService) {
        this.cryptoService = cryptoService;
    }

    public Map<String, Object> initializeDiffieHellman() throws Exception {
        String sessionId = UUID.randomUUID().toString();

        // Gerar par de chaves DH
        KeyPair keyPair = cryptoService.generateDHKeyPair();
        dhSessions.put(sessionId, keyPair);

        // Extrair parâmetros públicos
        byte[] publicKeyBytes = keyPair.getPublic().getEncoded();

        // Tentar extrair p, g e valor público (y) para interoperabilidade com clientes
        // JS/Node
        String primeHex = null;
        String generatorHex = null;
        String publicYHex = null;
        try {
            java.security.PublicKey pub = keyPair.getPublic();
            if (pub instanceof DHPublicKey) {
                DHPublicKey dhPub = (DHPublicKey) pub;
                DHParameterSpec params = dhPub.getParams();
                if (params != null) {
                    BigInteger p = params.getP();
                    BigInteger g = params.getG();
                    primeHex = p.toString(16);
                    generatorHex = g.toString(16);
                }

                // Valor público (y)
                try {
                    BigInteger y = dhPub.getY();
                    publicYHex = y.toString(16);
                } catch (Exception ignore) {
                    // ignore
                }
            }
        } catch (Exception ignore) {
            // Não essencial — retornamos pelo menos a chave pública X.509 em Base64
        }

        Map<String, Object> result = new HashMap<>();
        result.put("sessionId", sessionId);
        result.put("publicKey", Base64.getEncoder().encodeToString(publicKeyBytes));
        if (primeHex != null)
            result.put("prime", primeHex);
        if (generatorHex != null)
            result.put("generator", generatorHex);
        if (publicYHex != null)
            result.put("publicKeyHex", publicYHex);
        result.put("algorithm", "DH");
        result.put("keySize", 1024);
        result.put("timestamp", System.currentTimeMillis());

        return result;
    }

    public Map<String, Object> calculateSharedSecret(String sessionId, String otherPartyPublicKeyStr) throws Exception {
        KeyPair ourKeyPair = dhSessions.get(sessionId);
        if (ourKeyPair == null) {
            throw new RuntimeException("Sessão DH não encontrada: " + sessionId);
        }

        // Converter chave pública do outro participante
        byte[] otherPublicKeyBytes = Base64.getDecoder().decode(otherPartyPublicKeyStr);
        KeyFactory keyFactory = KeyFactory.getInstance("DH");
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(otherPublicKeyBytes);
        PublicKey otherPublicKey = keyFactory.generatePublic(keySpec);

        // Calcular segredo compartilhado
        byte[] sharedSecret = cryptoService.generateDHSharedSecret(ourKeyPair.getPrivate(), otherPublicKey);
        sharedSecrets.put(sessionId, sharedSecret);

        // Derivar chave AES do segredo
        SecretKey aesKey = cryptoService.deriveAESKeyFromDHSecret(sharedSecret);

        Map<String, Object> result = new HashMap<>();
        result.put("sessionId", sessionId);
        result.put("sharedSecret", Base64.getEncoder().encodeToString(sharedSecret));
        result.put("aesKey", Base64.getEncoder().encodeToString(aesKey.getEncoded()));
        result.put("success", true);
        result.put("keyAlgorithm", "AES");
        result.put("keySize", 128);

        return result;
    }

    public SecretKey getAESKeyForSession(String sessionId) throws Exception {
        byte[] sharedSecret = sharedSecrets.get(sessionId);
        if (sharedSecret == null) {
            throw new RuntimeException("Segredo compartilhado não encontrado para sessão: " + sessionId);
        }
        return cryptoService.deriveAESKeyFromDHSecret(sharedSecret);
    }

    public boolean sessionExists(String sessionId) {
        return dhSessions.containsKey(sessionId);
    }

    public void cleanupSession(String sessionId) {
        dhSessions.remove(sessionId);
        sharedSecrets.remove(sessionId);
    }

    public Map<String, String> getActiveSessions() {
        Map<String, String> sessions = new HashMap<>();
        dhSessions.forEach((id, keyPair) -> {
            sessions.put(id, "DH KeyPair - " + keyPair.getPublic().getAlgorithm());
        });
        return sessions;
    }

    public Map<String, Object> simulateDHAgreement() throws Exception {
        // Simular duas partes (Alice e Bob)
        Map<String, Object> alice = initializeDiffieHellman();
        Map<String, Object> bob = initializeDiffieHellman();

        String alicePublicKey = (String) alice.get("publicKey");
        String bobPublicKey = (String) bob.get("publicKey");

        // Alice calcula segredo com chave pública do Bob
        Map<String, Object> aliceShared = calculateSharedSecret(
                (String) alice.get("sessionId"),
                bobPublicKey);

        // Bob calcula segredo com chave pública da Alice
        Map<String, Object> bobShared = calculateSharedSecret(
                (String) bob.get("sessionId"),
                alicePublicKey);

        // Verificar se os segredos são iguais
        boolean keysMatch = aliceShared.get("sharedSecret").equals(bobShared.get("sharedSecret"));

        Map<String, Object> result = new HashMap<>();
        result.put("success", true);
        result.put("sessionIdA", alice.get("sessionId"));
        result.put("sessionIdB", bob.get("sessionId"));
        result.put("publicKeyA", alicePublicKey);
        result.put("publicKeyB", bobPublicKey);
        result.put("sharedSecretA", aliceShared.get("sharedSecret"));
        result.put("sharedSecretB", bobShared.get("sharedSecret"));
        result.put("aesKeyA", aliceShared.get("aesKey"));
        result.put("aesKeyB", bobShared.get("aesKey"));
        result.put("keysMatch", keysMatch);
        result.put("message", keysMatch ? "✅ Acordo DH bem-sucedido! Chaves AES idênticas geradas."
                : "❌ Erro: Segredos não coincidem");

        // Cleanup
        cleanupSession((String) alice.get("sessionId"));
        cleanupSession((String) bob.get("sessionId"));

        return result;
    }

    /**
     * Calcula segredo compartilhado quando o outro participante envia a chave
     * pública em formato HEX (big integer hex).
     * Isso torna possível interoperabilidade com clients que geram chaves DH como
     * bigints (frontend util CryptoUtils).
     */
    public Map<String, Object> calculateSharedSecretFromRawHex(String sessionId, String otherPublicHex)
            throws Exception {
        KeyPair ourKeyPair = dhSessions.get(sessionId);
        if (ourKeyPair == null) {
            throw new RuntimeException("Sessão DH não encontrada: " + sessionId);
        }

        // Extrair parâmetros DH (p, g) e o expoente privado x
        java.security.PublicKey pub = ourKeyPair.getPublic();
        if (!(pub instanceof DHPublicKey)) {
            throw new RuntimeException("Chave pública da sessão não é DH");
        }

        DHPublicKey ourPub = (DHPublicKey) pub;
        DHPrivateKey ourPriv = (DHPrivateKey) ourKeyPair.getPrivate();

        BigInteger p = ourPub.getParams().getP();
        BigInteger x = ourPriv.getX();

        // otherPublicHex é a representação hex do valor público (big integer)
        BigInteger otherPub = new BigInteger(otherPublicHex, 16);

        // Calcular segredo: otherPub^x mod p
        BigInteger sharedBI = otherPub.modPow(x, p);
        byte[] sharedSecret = sharedBI.toByteArray();

        // Armazenar e derivar AES
        sharedSecrets.put(sessionId, sharedSecret);

        SecretKey aesKey = cryptoService.deriveAESKeyFromDHSecret(sharedSecret);

        Map<String, Object> result = new HashMap<>();
        result.put("sessionId", sessionId);
        result.put("sharedSecret", Base64.getEncoder().encodeToString(sharedSecret));
        result.put("aesKey", Base64.getEncoder().encodeToString(aesKey.getEncoded()));
        result.put("success", true);
        result.put("keyAlgorithm", "AES");
        result.put("keySize", 128);

        return result;
    }

    // Permite armazenar um segredo compartilhado pré-calculado sob um sessionId
    public void storeSharedSecret(String sessionId, byte[] sharedSecret) {
        if (sessionId == null || sharedSecret == null)
            return;
        sharedSecrets.put(sessionId, sharedSecret);
    }

    public boolean hasSharedSecret(String sessionId) {
        return sharedSecrets.containsKey(sessionId);
    }
}