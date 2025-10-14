    package com.securemessaging.dto;

    import java.util.Map;

    public class KeyManagementDTO {
        private String publicKey;
        private String privateKey;
        private String keyFormat;
        private String keyType;
        private int keySize;
        private Map<String, Object> keyInfo;

        // Construtores
        public KeyManagementDTO() {
        }

        public KeyManagementDTO(String publicKey, String privateKey, String keyType, int keySize) {
            this.publicKey = publicKey;
            this.privateKey = privateKey;
            this.keyType = keyType;
            this.keySize = keySize;
            this.keyFormat = "PEM";
        }

        // Getters e Setters
        public String getPublicKey() {
            return publicKey;
        }

        public void setPublicKey(String publicKey) {
            this.publicKey = publicKey;
        }

        public String getPrivateKey() {
            return privateKey;
        }

        public void setPrivateKey(String privateKey) {
            this.privateKey = privateKey;
        }

        public String getKeyFormat() {
            return keyFormat;
        }

        public void setKeyFormat(String keyFormat) {
            this.keyFormat = keyFormat;
        }

        public String getKeyType() {
            return keyType;
        }

        public void setKeyType(String keyType) {
            this.keyType = keyType;
        }

        public int getKeySize() {
            return keySize;
        }

        public void setKeySize(int keySize) {
            this.keySize = keySize;
        }

        public Map<String, Object> getKeyInfo() {
            return keyInfo;
        }

        public void setKeyInfo(Map<String, Object> keyInfo) {
            this.keyInfo = keyInfo;
        }
    }