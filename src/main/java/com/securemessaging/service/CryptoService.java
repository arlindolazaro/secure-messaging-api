package com.securemessaging.service;

import org.bouncycastle.asn1.pkcs.RSAPrivateKey;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.X509Certificate;
import java.security.spec.*;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.util.Base64;
import java.util.Date;

@Service
public class CryptoService {

    static {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        }
    }

    // ========================= Métodos PEM =========================

    /**
     * Converte chave pública para formato PEM
     */
    public String publicKeyToPEM(PublicKey publicKey) {
        String base64Key = Base64.getEncoder().encodeToString(publicKey.getEncoded());
        return "-----BEGIN PUBLIC KEY-----\n" +
                formatBase64PEM(base64Key) +
                "-----END PUBLIC KEY-----";
    }

    /**
     * Converte chave privada para formato PEM
     */
    public String privateKeyToPEM(PrivateKey privateKey) {
        String base64Key = Base64.getEncoder().encodeToString(privateKey.getEncoded());
        return "-----BEGIN PRIVATE KEY-----\n" +
                formatBase64PEM(base64Key) +
                "-----END PRIVATE KEY-----";
    }

    /**
     * Formata Base64 em linhas de 64 caracteres
     */
    private String formatBase64PEM(String base64) {
        StringBuilder formatted = new StringBuilder();
        for (int i = 0; i < base64.length(); i += 64) {
            int end = Math.min(i + 64, base64.length());
            formatted.append(base64.substring(i, end)).append("\n");
        }
        return formatted.toString();
    }

    /**
     * Garante que a chave está em formato PEM
     */
    public String ensurePEMFormat(String keyString, boolean isPublic) {
        if (keyString == null)
            return null;

        String trimmed = keyString.trim();

        // Se já está em formato PEM, retorna como está
        if (trimmed.startsWith("-----BEGIN") && trimmed.endsWith("KEY-----")) {
            return trimmed;
        }

        // Se é Base64 puro, converte para PEM
        try {
            String cleanBase64 = trimmed.replaceAll("[\\r\\n\\s]", "");

            // Verifica se é Base64 válido
            Base64.getDecoder().decode(cleanBase64);

            if (isPublic) {
                return "-----BEGIN PUBLIC KEY-----\n" +
                        formatBase64PEM(cleanBase64) +
                        "-----END PUBLIC KEY-----";
            } else {
                return "-----BEGIN PRIVATE KEY-----\n" +
                        formatBase64PEM(cleanBase64) +
                        "-----END PRIVATE KEY-----";
            }
        } catch (Exception e) {
            throw new IllegalArgumentException("String de chave em formato inválido: " + e.getMessage());
        }
    }

    // ========================= X500Name / Cert generation
    // =========================
    private X500Name buildX500Name(String commonName, String organization, String organizationalUnit,
            String locality, String state, String country) {
        X500NameBuilder builder = new X500NameBuilder();

        if (commonName != null && !commonName.trim().isEmpty()) {
            builder.addRDN(BCStyle.CN, commonName.trim());
        } else {
            builder.addRDN(BCStyle.CN, "SecureMessaging User");
        }

        if (organization != null && !organization.trim().isEmpty()) {
            builder.addRDN(BCStyle.O, organization.trim());
        } else {
            builder.addRDN(BCStyle.O, "SecureMessaging");
        }

        if (organizationalUnit != null && !organizationalUnit.trim().isEmpty()) {
            builder.addRDN(BCStyle.OU, organizationalUnit.trim());
        }

        if (locality != null && !locality.trim().isEmpty()) {
            builder.addRDN(BCStyle.L, locality.trim());
        }

        if (state != null && !state.trim().isEmpty()) {
            builder.addRDN(BCStyle.ST, state.trim());
        }

        if (country != null && !country.trim().isEmpty() && country.trim().length() == 2) {
            builder.addRDN(BCStyle.C, country.trim().toUpperCase());
        } else {
            builder.addRDN(BCStyle.C, "MZ");
        }

        return builder.build();
    }

    public X509Certificate generateCertificate(KeyPair keyPair, String commonName, String organization,
            String organizationalUnit, String locality, String state,
            String country, int validDays) throws Exception {
        X500Name subject = buildX500Name(commonName, organization, organizationalUnit, locality, state, country);
        X500Name issuer = subject;

        BigInteger serial = BigInteger.valueOf(System.currentTimeMillis());
        ZonedDateTime notBefore = ZonedDateTime.now(ZoneId.of("UTC")).minusMinutes(1);
        ZonedDateTime notAfter = notBefore.plusDays(validDays);

        JcaX509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                issuer, serial, Date.from(notBefore.toInstant()),
                Date.from(notAfter.toInstant()), subject, keyPair.getPublic());

        var signer = new JcaContentSignerBuilder("SHA256withRSA").setProvider("BC").build(keyPair.getPrivate());
        var holder = certBuilder.build(signer);
        return new JcaX509CertificateConverter().setProvider("BC").getCertificate(holder);
    }

    public X509Certificate generateRootCertificate(KeyPair keyPair, String commonName, String organization,
            String organizationalUnit, String locality, String state,
            String country, int validDays) throws Exception {
        return generateCertificate(keyPair, commonName, organization, organizationalUnit, locality, state, country,
                validDays);
    }

    public X509Certificate generateSignedCertificate(
            PublicKey userPublicKey,
            PrivateKey caPrivateKey,
            String subjectCommonName, String subjectOrganization, String subjectOrganizationalUnit,
            String subjectLocality, String subjectProvince, String subjectCountry,
            String issuerCommonName, String issuerOrganization, String issuerOrganizationalUnit,
            String issuerLocality, String issuerProvince, String issuerCountry,
            int validDays) throws Exception {

        X500Name subject = buildX500Name(subjectCommonName, subjectOrganization, subjectOrganizationalUnit,
                subjectLocality, subjectProvince, subjectCountry);
        X500Name issuer = buildX500Name(issuerCommonName, issuerOrganization, issuerOrganizationalUnit,
                issuerLocality, issuerProvince, issuerCountry);

        BigInteger serial = BigInteger.valueOf(System.currentTimeMillis());
        ZonedDateTime notBefore = ZonedDateTime.now(ZoneId.of("UTC")).minusMinutes(1);
        ZonedDateTime notAfter = notBefore.plusDays(validDays);

        JcaX509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(issuer, serial,
                Date.from(notBefore.toInstant()), Date.from(notAfter.toInstant()), subject, userPublicKey);

        var signer = new JcaContentSignerBuilder("SHA256withRSA").setProvider("BC").build(caPrivateKey);
        var holder = certBuilder.build(signer);
        return new JcaX509CertificateConverter().setProvider("BC").getCertificate(holder);
    }

    // ========================= Key utilities =========================
    public String keyToString(Key key) {
        return Base64.getEncoder().encodeToString(key.getEncoded());
    }

    public KeyPair generateRSAKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(1024);
        return keyGen.generateKeyPair();
    }

    public KeyPair generateRSAKeyPair(int keySize) throws NoSuchAlgorithmException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(keySize);
        return keyGen.generateKeyPair();
    }

    public KeyPair generateDHKeyPair() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DH");

        byte[] seed = new byte[16];
        SecureRandom strongRnd;
        try {
            strongRnd = SecureRandom.getInstanceStrong();
        } catch (Exception ex) {
            strongRnd = new SecureRandom();
        }
        strongRnd.nextBytes(seed);

        SecureRandom seededRnd;
        try {
            seededRnd = SecureRandom.getInstance("SHA1PRNG");
            seededRnd.setSeed(seed);
        } catch (Exception ex) {
            seededRnd = new SecureRandom(seed);
        }

        keyGen.initialize(1024, seededRnd);
        return keyGen.generateKeyPair();
    }

    public byte[] generateDHSharedSecret(PrivateKey privateKey, PublicKey publicKey) throws Exception {
        KeyAgreement keyAgreement = KeyAgreement.getInstance("DH");
        keyAgreement.init(privateKey);
        keyAgreement.doPhase(publicKey, true);
        return keyAgreement.generateSecret();
    }

    public SecretKey deriveAESKeyFromDHSecret(byte[] dhSecret) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] keyMaterial = digest.digest(dhSecret);
        byte[] aesKeyBytes = new byte[16];
        System.arraycopy(keyMaterial, 0, aesKeyBytes, 0, 16);
        return new SecretKeySpec(aesKeyBytes, "AES");
    }

    // ========================= AES helpers =========================
    public String encryptWithAES(String data, SecretKey aesKey) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, aesKey);
        byte[] iv = cipher.getIV();
        byte[] encrypted = cipher.doFinal(data.getBytes("UTF-8"));

        byte[] out = new byte[iv.length + encrypted.length];
        System.arraycopy(iv, 0, out, 0, iv.length);
        System.arraycopy(encrypted, 0, out, iv.length, encrypted.length);

        return Base64.getEncoder().encodeToString(out);
    }

    public String decryptWithAES(String encryptedData, SecretKey aesKey) throws Exception {
        try {
            String cleanData = encryptedData.replaceAll("\\s+", "").trim();

            if (!isValidBase64(cleanData)) {
                throw new IllegalArgumentException("Formato Base64 inválido");
            }

            byte[] data = Base64.getDecoder().decode(cleanData);
            byte[] iv = new byte[16];
            System.arraycopy(data, 0, iv, 0, 16);
            byte[] encrypted = new byte[data.length - 16];
            System.arraycopy(data, 16, encrypted, 0, encrypted.length);

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, aesKey, new IvParameterSpec(iv));
            byte[] decrypted = cipher.doFinal(encrypted);

            return new String(decrypted, "UTF-8");
        } catch (Exception e) {
            throw new RuntimeException("Erro na decriptação AES: " + e.getMessage(), e);
        }
    }

    // ========================= PGP-style hybrid: encrypt -> JSON
    // =========================
    public String encryptPGPStyle(String data, PublicKey publicKey) throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(128);
        SecretKey sessionKey = keyGen.generateKey();

        Cipher aesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        aesCipher.init(Cipher.ENCRYPT_MODE, sessionKey);
        byte[] iv = aesCipher.getIV();
        byte[] encryptedData = aesCipher.doFinal(data.getBytes("UTF-8"));

        Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        rsaCipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedSessionKey = rsaCipher.doFinal(sessionKey.getEncoded());

        String hash = hashWithSHA256(data);

        String json = String.format(
                "{\"encryptedKey\":\"%s\",\"iv\":\"%s\",\"ciphertext\":\"%s\",\"hash\":\"%s\"}",
                Base64.getEncoder().encodeToString(encryptedSessionKey),
                Base64.getEncoder().encodeToString(iv),
                Base64.getEncoder().encodeToString(encryptedData),
                hash);

        return json;
    }

    public String decryptPGPStyle(String encryptedData, PrivateKey privateKey) throws Exception {
        try {
            if (encryptedData == null) {
                throw new IllegalArgumentException("Dados criptografados é nulo");
            }

            String input = encryptedData.trim();
            if (input.length() >= 2 && input.startsWith("\"") && input.endsWith("\"")) {
                input = input.substring(1, input.length() - 1).trim();
            }

            // 1) Tentar parsing JSON
            try {
                com.fasterxml.jackson.databind.ObjectMapper mapper = new com.fasterxml.jackson.databind.ObjectMapper();
                com.fasterxml.jackson.databind.JsonNode node = mapper.readTree(input);
                if (node.has("encryptedKey") && node.has("iv") && node.has("ciphertext")) {
                    String encryptedKeyB64 = node.get("encryptedKey").asText();
                    String ivB64 = node.get("iv").asText();
                    String ciphertextB64 = node.get("ciphertext").asText();
                    String hashB64 = node.has("hash") ? node.get("hash").asText() : null;

                    byte[] encryptedKeyBytes = Base64.getDecoder().decode(encryptedKeyB64);
                    byte[] ivBytes = Base64.getDecoder().decode(ivB64);
                    byte[] ciphertextBytes = Base64.getDecoder().decode(ciphertextB64);

                    byte[] sessionKeyBytes = null;
                    Exception lastEx = null;

                    // Tentar diferentes métodos de decriptação RSA
                    String[] rsaMethods = {
                            "RSA/ECB/OAEPWithSHA-256AndMGF1Padding",
                            "RSA/ECB/OAEPWithSHA-1AndMGF1Padding",
                            "RSA/ECB/PKCS1Padding"
                    };

                    for (String method : rsaMethods) {
                        try {
                            Cipher rsaCipher = Cipher.getInstance(method);
                            rsaCipher.init(Cipher.DECRYPT_MODE, privateKey);
                            sessionKeyBytes = rsaCipher.doFinal(encryptedKeyBytes);
                            lastEx = null;
                            break;
                        } catch (Exception ex) {
                            lastEx = ex;
                        }
                    }

                    if (sessionKeyBytes == null) {
                        throw new RuntimeException(
                                "Falha ao decriptar chave RSA (tentadas OAEP-SHA256, OAEP-SHA1, PKCS1)", lastEx);
                    }

                    SecretKey sessionKey = new SecretKeySpec(sessionKeyBytes, "AES");

                    // Tentar AES-GCM primeiro (iv 12 bytes)
                    if (ivBytes != null && ivBytes.length == 12) {
                        try {
                            Cipher aesGcm = Cipher.getInstance("AES/GCM/NoPadding");
                            GCMParameterSpec gcmSpec = new GCMParameterSpec(128, ivBytes);
                            aesGcm.init(Cipher.DECRYPT_MODE, sessionKey, gcmSpec);
                            byte[] plain = aesGcm.doFinal(ciphertextBytes);
                            String result = new String(plain, "UTF-8");

                            if (hashB64 != null) {
                                String calculated = hashWithSHA256(result);
                                if (!calculated.equals(hashB64)) {
                                    throw new SecurityException("Falha na verificação de integridade (hash mismatch)");
                                }
                            }
                            return result;
                        } catch (Exception e) {
                            // Fall through to CBC
                        }
                    }

                    // Usar AES-CBC (iv 16 bytes)
                    if (ivBytes != null && ivBytes.length == 16) {
                        Cipher aesCbc = Cipher.getInstance("AES/CBC/PKCS5Padding");
                        aesCbc.init(Cipher.DECRYPT_MODE, sessionKey, new IvParameterSpec(ivBytes));
                        byte[] plain = aesCbc.doFinal(ciphertextBytes);
                        String result = new String(plain, "UTF-8");
                        if (hashB64 != null) {
                            String calculated = hashWithSHA256(result);
                            if (!calculated.equals(hashB64)) {
                                throw new SecurityException("Falha na verificação de integridade (hash mismatch)");
                            }
                        }
                        return result;
                    }

                    throw new IllegalArgumentException(
                            "IV com tamanho inesperado: " + (ivBytes == null ? "null" : ivBytes.length));
                }
            } catch (com.fasterxml.jackson.core.JsonProcessingException jpe) {
                // Não é JSON, tentar formato legado
            }

            // 2) Formato legado
            String base64Clean = encryptedData.replaceAll("[\\r\\n\\s\"]", "").trim();

            if (!isValidBase64(base64Clean))
                throw new IllegalArgumentException("Formato Base64 inválido");

            byte[] data = Base64.getDecoder().decode(base64Clean);

            int rsaKeyBytes = 128;
            if (privateKey instanceof java.security.interfaces.RSAPrivateKey) {
                java.security.interfaces.RSAPrivateKey rsaPriv = (java.security.interfaces.RSAPrivateKey) privateKey;
                rsaKeyBytes = (rsaPriv.getModulus().bitLength() + 7) / 8;
            }

            int headerLen = 16 + rsaKeyBytes;
            if (data.length <= headerLen)
                throw new IllegalArgumentException("Dados criptografados muito curtos");

            byte[] iv = new byte[16];
            System.arraycopy(data, 0, iv, 0, 16);

            byte[] encryptedSessionKey = new byte[rsaKeyBytes];
            System.arraycopy(data, 16, encryptedSessionKey, 0, rsaKeyBytes);

            byte[] encryptedMessage = new byte[data.length - headerLen];
            System.arraycopy(data, headerLen, encryptedMessage, 0, encryptedMessage.length);

            Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            rsaCipher.init(Cipher.DECRYPT_MODE, privateKey);
            byte[] sessionKeyBytes = rsaCipher.doFinal(encryptedSessionKey);
            SecretKey sessionKey = new SecretKeySpec(sessionKeyBytes, "AES");

            Cipher aesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            aesCipher.init(Cipher.DECRYPT_MODE, sessionKey, new IvParameterSpec(iv));
            byte[] decryptedData = aesCipher.doFinal(encryptedMessage);

            return new String(decryptedData, "UTF-8");

        } catch (IllegalArgumentException e) {
            String dbg = "(debug) encryptedData length=" + (encryptedData != null ? encryptedData.length() : 0)
                    + ", cleanedBase64=" + (encryptedData != null ? debugBase64(encryptedData) : "NULL");
            throw new RuntimeException("Erro no formato Base64: " + e.getMessage() + " " + dbg, e);
        } catch (Exception e) {
            String dbg = "(debug) encryptedData length=" + (encryptedData != null ? encryptedData.length() : 0)
                    + ", cleanedBase64=" + (encryptedData != null ? debugBase64(encryptedData) : "NULL");
            throw new RuntimeException("Erro na decriptação PGP: " + e.getMessage() + " " + dbg, e);
        }
    }

    private boolean isValidBase64(String data) {
        if (data == null || data.isEmpty())
            return false;
        try {
            Base64.getDecoder().decode(data);
            return true;
        } catch (IllegalArgumentException e) {
            return false;
        }
    }

    public String debugBase64(String data) {
        if (data == null)
            return "NULL";
        String clean = data.replaceAll("\\s+", "").trim();
        return "Length: " + clean.length() + ", Valid: " + isValidBase64(clean);
    }

    // ========================= Hashes & Signatures =========================
    public String hashWithSHA256(String data) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(data.getBytes());
        return Base64.getEncoder().encodeToString(hash);
    }

    public String hashWithSHA3_256(String data) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA3-256");
        byte[] hash = digest.digest(data.getBytes());
        return Base64.getEncoder().encodeToString(hash);
    }

    public String hashWithSHA3_512(String data) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA3-512");
        byte[] hash = digest.digest(data.getBytes());
        return Base64.getEncoder().encodeToString(hash);
    }

    public String signData(String data, PrivateKey privateKey) throws Exception {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKey);
        signature.update(data.getBytes());
        return Base64.getEncoder().encodeToString(signature.sign());
    }

    public boolean verifySignature(String data, String signatureData, PublicKey publicKey) throws Exception {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initVerify(publicKey);
        signature.update(data.getBytes());
        return signature.verify(Base64.getDecoder().decode(signatureData));
    }

    // ========================= Conversões melhoradas =========================
    public PublicKey stringToPublicKey(String publicKeyStr) throws Exception {
        if (publicKeyStr == null || publicKeyStr.trim().isEmpty()) {
            throw new IllegalArgumentException("Chave pública está vazia");
        }

        String cleaned = publicKeyStr.trim();

        // Remove cabeçalhos PEM se existirem
        if (cleaned.contains("-----BEGIN")) {
            cleaned = cleaned.replaceAll("-----BEGIN [A-Z ]*KEY-----", "")
                    .replaceAll("-----END [A-Z ]*KEY-----", "")
                    .replaceAll("[\\r\\n\\s]", "");
        }

        try {
            byte[] keyBytes = Base64.getDecoder().decode(cleaned);
            X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            return kf.generatePublic(spec);
        } catch (Exception e) {
            throw new IllegalArgumentException("Falha ao converter string para chave pública: " + e.getMessage(), e);
        }
    }

    public PrivateKey stringToPrivateKey(String privateKeyStr) throws Exception {
        if (privateKeyStr == null || privateKeyStr.trim().isEmpty()) {
            throw new IllegalArgumentException("Chave privada está vazia");
        }

        String cleaned = privateKeyStr.trim();

        // Remove cabeçalhos PEM se existirem
        if (cleaned.contains("-----BEGIN")) {
            cleaned = cleaned.replaceAll("-----BEGIN [A-Z ]*KEY-----", "")
                    .replaceAll("-----END [A-Z ]*KEY-----", "")
                    .replaceAll("[\\r\\n\\s]", "");
        }

        byte[] keyBytes = Base64.getDecoder().decode(cleaned);

        // Tenta PKCS#8 primeiro
        try {
            PKCS8EncodedKeySpec pkcs8Spec = new PKCS8EncodedKeySpec(keyBytes);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            return kf.generatePrivate(pkcs8Spec);
        } catch (Exception pkcs8Ex) {
            // Tenta PKCS#1
            try {
                RSAPrivateKey rsa = RSAPrivateKey.getInstance(keyBytes);
                RSAPrivateCrtKeySpec keySpec = new RSAPrivateCrtKeySpec(
                        rsa.getModulus(),
                        rsa.getPublicExponent(),
                        rsa.getPrivateExponent(),
                        rsa.getPrime1(),
                        rsa.getPrime2(),
                        rsa.getExponent1(),
                        rsa.getExponent2(),
                        rsa.getCoefficient());
                KeyFactory kf = KeyFactory.getInstance("RSA");
                return kf.generatePrivate(keySpec);
            } catch (Exception pkcs1Ex) {
                throw new IllegalArgumentException("Falha ao parsear chave privada: " + pkcs1Ex.getMessage());
            }
        }
    }

    public PrivateKey stringToPrivateKey(String privateKeyStr, String algorithm) throws Exception {
        if (privateKeyStr == null)
            throw new IllegalArgumentException("Chave privada está vazia");

        String cleaned = privateKeyStr.replaceAll("-----BEGIN [A-Z ]*KEY-----", "")
                .replaceAll("-----END [A-Z ]*KEY-----", "")
                .replaceAll("[\\r\\n\\s]", "");

        byte[] keyBytes = Base64.getDecoder().decode(cleaned);
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance(algorithm);
        return kf.generatePrivate(spec);
    }

    // ========================= IV helpers =========================
    public byte[] generateSecureIV() {
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        return iv;
    }

    public String ivToString(byte[] iv) {
        return Base64.getEncoder().encodeToString(iv);
    }

    public byte[] stringToIv(String ivString) {
        return Base64.getDecoder().decode(ivString);
    }
}