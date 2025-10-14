package com.securemessaging.controller;

import com.securemessaging.dto.CertificateDTO;
import com.securemessaging.service.CertificateService;
import com.securemessaging.service.PDFGenerationService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/pdf")
@CrossOrigin(origins = "*")
@Tag(name = "PDF Export", description = "API para exportação de certificados em PDF")
public class PDFExportController {

    private final PDFGenerationService pdfGenerationService;
    private final CertificateService certificateService;

    public PDFExportController(PDFGenerationService pdfGenerationService, CertificateService certificateService) {
        this.pdfGenerationService = pdfGenerationService;
        this.certificateService = certificateService;
    }

    @Operation(summary = "Exportar certificado para PDF", description = "Gera PDF do certificado para download")
    @GetMapping("/certificates/{certificateId}/export")
    public ResponseEntity<?> exportCertificatePDF(@PathVariable Long certificateId) {
        try {
            CertificateDTO certificate = certificateService.getCertificateById(certificateId)
                    .orElseThrow(() -> new RuntimeException("Certificado não encontrado"));

            byte[] pdfBytes = pdfGenerationService.generateCertificatePDF(certificate);

            String fileName = String.format("certificado_%s.pdf",
                    certificate.getSubjectName().replaceAll("[^a-zA-Z0-9]", "_"));

            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_PDF);
            headers.setContentDispositionFormData("attachment", fileName);
            headers.setContentLength(pdfBytes.length);

            return new ResponseEntity<>(pdfBytes, headers, HttpStatus.OK);
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of(
                            "success", false,
                            "error", "Erro ao gerar PDF: " + e.getMessage()));
        }
    }

    @Operation(summary = "Gerar PDF como Base64", description = "Gera PDF do certificado em Base64")
    @GetMapping("/certificates/{certificateId}/base64")
    public ResponseEntity<?> generateCertificateBase64(@PathVariable Long certificateId) {
        try {
            CertificateDTO certificate = certificateService.getCertificateById(certificateId)
                    .orElseThrow(() -> new RuntimeException("Certificado não encontrado"));

            byte[] pdfBytes = pdfGenerationService.generateCertificatePDF(certificate);
            String base64PDF = pdfGenerationService.pdfToBase64(pdfBytes);

            return ResponseEntity.ok(Map.of(
                    "success", true,
                    "base64", base64PDF,
                    "fileName", String.format("certificado_%s.pdf",
                            certificate.getSubjectName().replaceAll("[^a-zA-Z0-9]", "_")),
                    "message", "PDF gerado com sucesso"));
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of(
                            "success", false,
                            "error", "Erro ao gerar PDF: " + e.getMessage()));
        }
    }

    @Operation(summary = "Health check")
    @GetMapping("/health")
    public ResponseEntity<?> healthCheck() {
        try {
            return ResponseEntity.ok(Map.of(
                    "status", "UP",
                    "service", "PDF Export",
                    "timestamp", java.time.LocalDateTime.now()));
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of(
                            "status", "DOWN",
                            "error", e.getMessage()));
        }
    }
}