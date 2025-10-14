package com.securemessaging.service;

import com.securemessaging.dto.CertificateDTO;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.PDPageContentStream;
import org.apache.pdfbox.pdmodel.font.PDFont;
import org.apache.pdfbox.pdmodel.font.PDType1Font;
import org.apache.pdfbox.pdmodel.font.Standard14Fonts;
import org.springframework.stereotype.Service;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.time.format.DateTimeFormatter;
import java.util.Base64;

@Service
public class PDFGenerationService {

    private static final DateTimeFormatter DATE_FORMATTER = DateTimeFormatter.ofPattern("dd/MM/yyyy HH:mm:ss");

    public byte[] generateCertificatePDF(CertificateDTO certificate) throws IOException {
        try (PDDocument document = new PDDocument();
                ByteArrayOutputStream outputStream = new ByteArrayOutputStream()) {

            PDPage page = new PDPage();
            document.addPage(page);

            try (PDPageContentStream contentStream = new PDPageContentStream(document, page)) {
                PDFont fontBold = new PDType1Font(Standard14Fonts.FontName.HELVETICA_BOLD);
                PDFont fontNormal = new PDType1Font(Standard14Fonts.FontName.HELVETICA);

                drawCenteredText(contentStream, "CERTIFICADO DIGITAL", 300, 750, fontBold, 16);
                drawCenteredText(contentStream,
                        "Documento gerado em: " + java.time.LocalDateTime.now().format(DATE_FORMATTER),
                        300, 730, fontNormal, 10);

                contentStream.setLineWidth(1f);
                contentStream.moveTo(50, 720);
                contentStream.lineTo(550, 720);
                contentStream.stroke();

                int yPosition = 690;
                drawField(contentStream, "Nome do Subject:", certificate.getSubjectName(), 50, yPosition, fontBold,
                        fontNormal);
                yPosition -= 20;
                drawField(contentStream, "Emissor:", certificate.getIssuerName(), 50, yPosition, fontBold, fontNormal);
                yPosition -= 20;
                drawField(contentStream, "Número de Série:", certificate.getSerialNumber(), 50, yPosition, fontBold,
                        fontNormal);
                yPosition -= 20;

                String validFrom = certificate.getValidFrom() != null
                        ? certificate.getValidFrom().format(DATE_FORMATTER)
                        : "N/A";
                drawField(contentStream, "Válido de:", validFrom, 50, yPosition, fontBold, fontNormal);
                yPosition -= 20;

                String validTo = certificate.getValidTo() != null ? certificate.getValidTo().format(DATE_FORMATTER)
                        : "N/A";
                drawField(contentStream, "Válido até:", validTo, 50, yPosition, fontBold, fontNormal);
                yPosition -= 20;

                String status = certificate.isRevoked() ? "REVOGADO" : "VÁLIDO";
                drawField(contentStream, "Estado:", status, 50, yPosition, fontBold, fontNormal);
            }

            document.save(outputStream);
            return outputStream.toByteArray();
        }
    }

    private void drawField(PDPageContentStream contentStream, String label, String value, float x, float y,
            PDFont fontBold, PDFont fontNormal) throws IOException {
        contentStream.setFont(fontBold, 10);
        contentStream.beginText();
        contentStream.newLineAtOffset(x, y);
        contentStream.showText(label);
        contentStream.endText();

        contentStream.setFont(fontNormal, 10);
        contentStream.beginText();
        contentStream.newLineAtOffset(x + 120, y);
        contentStream.showText(value != null ? value : "N/A");
        contentStream.endText();
    }

    private void drawCenteredText(PDPageContentStream contentStream, String text, float centerX, float y,
            PDFont font, float fontSize) throws IOException {
        contentStream.setFont(font, fontSize);
        float textWidth = font.getStringWidth(text) / 1000 * fontSize;
        float x = centerX - (textWidth / 2);

        contentStream.beginText();
        contentStream.newLineAtOffset(x, y);
        contentStream.showText(text);
        contentStream.endText();
    }

    public String pdfToBase64(byte[] pdfBytes) {
        return Base64.getEncoder().encodeToString(pdfBytes);
    }
}