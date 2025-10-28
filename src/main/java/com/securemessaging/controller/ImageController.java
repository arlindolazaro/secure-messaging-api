package com.securemessaging.controller;

import com.securemessaging.service.MessageService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.util.Map;

@RestController
@RequestMapping("/api/images")
@CrossOrigin(origins = "*")
public class ImageController {

    @Autowired
    private MessageService messageService;

    @PostMapping("/send")
    public ResponseEntity<?> sendEncryptedImage(
            @RequestParam Long senderId,
            @RequestParam Long receiverId,
            @RequestParam MultipartFile image,
            @RequestParam(required = false) String fileHash) {
        try {
            if (image.isEmpty()) {
                return ResponseEntity.badRequest().body(Map.of(
                        "success", false,
                        "error", "Imagem vazia"));
            }

            var message = messageService.sendEncryptedImage(senderId, receiverId, image, fileHash);

            return ResponseEntity.ok(Map.of(
                    "success", true,
                    "message", "Imagem enviada com sucesso",
                    "data", message));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of(
                    "success", false,
                    "error", e.getMessage()));
        }
    }

    @GetMapping("/{messageId}/preview")
    public ResponseEntity<?> getImagePreview(
            @PathVariable Long messageId,
            @RequestParam Long userId) {
        try {
            byte[] imageBytes = messageService.retrieveEncryptedImage(messageId, userId);
            var message = messageService.getMessageById(messageId);

            String base64Image = java.util.Base64.getEncoder().encodeToString(imageBytes);

            MediaType mediaType = MediaType.IMAGE_JPEG;
            if (message.getFileType() != null) {
                try {
                    mediaType = MediaType.parseMediaType(message.getFileType());
                } catch (Exception e) {
                }
            }

            Map<String, String> response = Map.of(
                    "success", "true",
                    "base64", "data:" + mediaType.toString() + ";base64," + base64Image,
                    "fileType", message.getFileType() != null ? message.getFileType() : "image/jpeg",
                    "fileName", message.getFileName() != null ? message.getFileName() : "image.jpg",
                    "message", "Preview gerado com sucesso");

            return ResponseEntity.ok(response);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of(
                    "success", false,
                    "error", e.getMessage()));
        }
    }

    @GetMapping("/{messageId}/download")
    public ResponseEntity<?> downloadImage(
            @PathVariable Long messageId,
            @RequestParam Long userId) {
        try {
            byte[] imageBytes = messageService.retrieveEncryptedImage(messageId, userId);
            var message = messageService.getMessageById(messageId);

            MediaType mediaType = MediaType.IMAGE_JPEG;
            if (message.getFileType() != null) {
                try {
                    mediaType = MediaType.parseMediaType(message.getFileType());
                } catch (Exception e) {
                    mediaType = MediaType.IMAGE_JPEG;
                }
            }

            String fileName = message.getFileName() != null ? message.getFileName() : "image.jpg";

            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(mediaType);
            headers.setContentDispositionFormData("attachment", fileName);
            headers.setContentLength(imageBytes.length);

            return new ResponseEntity<>(imageBytes, headers, HttpStatus.OK);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of(
                    "success", false,
                    "error", e.getMessage()));
        }
    }
}