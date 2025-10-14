package com.securemessaging.service;

import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Base64;
import java.util.UUID;

@Service
public class FileStorageService {

    private final Path fileStorageLocation;
    private final CryptoService cryptoService;

    public FileStorageService(CryptoService cryptoService) {
        this.cryptoService = cryptoService;
        this.fileStorageLocation = Paths.get("uploads").toAbsolutePath().normalize();

        try {
            Files.createDirectories(this.fileStorageLocation);
        } catch (Exception ex) {
            throw new RuntimeException("Could not create upload directory", ex);
        }
    }

    /**
     * Armazena e criptografa um arquivo
     */
    public String storeAndEncryptFile(MultipartFile file, SecretKey aesKey) throws Exception {
        String fileName = UUID.randomUUID().toString() + "_" + file.getOriginalFilename();
        Path targetLocation = this.fileStorageLocation.resolve(fileName);

        // ✅ CORREÇÃO: Usar bytes diretamente em vez de converter para String
        byte[] fileBytes = file.getBytes();
        String encryptedContent = cryptoService.encryptWithAES(Base64.getEncoder().encodeToString(fileBytes), aesKey);

        Files.write(targetLocation, encryptedContent.getBytes());
        return fileName;
    }

    /**
     * Decriptografa e recupera um arquivo
     */
    public byte[] decryptAndRetrieveFile(String fileName, SecretKey aesKey) throws Exception {
        Path filePath = this.fileStorageLocation.resolve(fileName).normalize();
        byte[] encryptedContent = Files.readAllBytes(filePath);

        // ✅ CORREÇÃO: Decodificar Base64 após descriptografia
        String decryptedContent = cryptoService.decryptWithAES(new String(encryptedContent), aesKey);
        return Base64.getDecoder().decode(decryptedContent);
    }

    /**
     * Converte imagem para Base64 (para preview)
     */
    public String imageToBase64(byte[] imageBytes) {
        return Base64.getEncoder().encodeToString(imageBytes);
    }

    /**
     * Calcula hash do arquivo para integridade
     */
    public String calculateFileHash(byte[] fileBytes) throws Exception {
        // ✅ CORREÇÃO: Usar bytes diretamente para hash
        return cryptoService.hashWithSHA256(Base64.getEncoder().encodeToString(fileBytes));
    }

    /**
     * Valida tipo de arquivo (segurança)
     */
    public boolean isValidImageType(String fileType) {
        return fileType != null && (fileType.equals("image/jpeg") ||
                fileType.equals("image/png") ||
                fileType.equals("image/gif") ||
                fileType.equals("image/webp"));
    }

    /**
     * Remove arquivo do storage
     */
    public void deleteFile(String fileName) throws IOException {
        Path filePath = this.fileStorageLocation.resolve(fileName).normalize();
        Files.deleteIfExists(filePath);
    }

    /**
     * ✅ NOVO: Armazenar arquivo sem criptografia (para imagens)
     */
    public String storeFile(MultipartFile file) throws Exception {
        String fileName = UUID.randomUUID().toString() + "_" + file.getOriginalFilename();
        Path targetLocation = this.fileStorageLocation.resolve(fileName);

        Files.write(targetLocation, file.getBytes());
        return fileName;
    }

    /**
     * ✅ NOVO: Recuperar arquivo sem criptografia
     */
    public byte[] retrieveFile(String fileName) throws Exception {
        Path filePath = this.fileStorageLocation.resolve(fileName).normalize();
        return Files.readAllBytes(filePath);
    }
}