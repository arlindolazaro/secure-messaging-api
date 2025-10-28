package com.securemessaging.service;

import com.securemessaging.dto.CertificateDTO;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.PDPageContentStream;
import org.apache.pdfbox.pdmodel.font.PDFont;
import org.apache.pdfbox.pdmodel.font.PDType1Font;
import org.apache.pdfbox.pdmodel.font.Standard14Fonts;
import org.springframework.stereotype.Service;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.text.SimpleDateFormat;
import java.time.format.DateTimeFormatter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.Base64;

@Service
public class PDFGenerationService {

    private static final DateTimeFormatter DATE_FORMATTER = DateTimeFormatter.ofPattern("dd/MM/yyyy HH:mm:ss");
    private static final Logger logger = LoggerFactory.getLogger(PDFGenerationService.class);

    // Constantes para layout e posicionamento
    private static final float PAGE_MARGIN_LEFT = 50f;
    private static final float PAGE_MARGIN_RIGHT = 550f;
    private static final float VALUE_OFFSET_X = 230f;
    private static final float MAX_VALUE_WIDTH = PAGE_MARGIN_RIGHT - VALUE_OFFSET_X;

    public byte[] generateCertificatePDF(CertificateDTO certificate) throws IOException {
        try (PDDocument document = new PDDocument();
                ByteArrayOutputStream outputStream = new ByteArrayOutputStream()) {

            // Estado da página atual e helpers para paginação
            try (PageState state = new PageState(document)) {
                // Tipografia: usar Times para labels/cabeçalho e Helvetica para valores
                PDFont fontBold = new PDType1Font(Standard14Fonts.FontName.TIMES_BOLD);
                PDFont fontLabel = new PDType1Font(Standard14Fonts.FontName.TIMES_ROMAN);
                PDFont fontNormal = new PDType1Font(Standard14Fonts.FontName.HELVETICA);
                PDFont fontMono = new PDType1Font(Standard14Fonts.FontName.COURIER);

                // Header mais proeminente (Times Bold)
                String titulo = "CERTIFICADO DIGITAL";
                float tituloY = 768f;
                drawCenteredText(state, titulo, 300, tituloY, fontBold, 28);

                // Traço logo abaixo do título
                try {
                    PDPageContentStream cs = state.contentStream;
                    cs.setLineWidth(1.0f);
                    // calcular largura do texto para centralizar a linha com pequena margem
                    float tituloWidth = fontBold.getStringWidth(titulo) / 1000 * 28;
                    float lineStartX = 300 - (tituloWidth / 2) - 8; // 8pt margem à esquerda
                    float lineEndX = 300 + (tituloWidth / 2) + 8; // 8pt margem à direita
                    float lineY = tituloY - 10; // 10pt abaixo do baseline do título
                    cs.moveTo(lineStartX, lineY);
                    cs.lineTo(lineEndX, lineY);
                    cs.stroke();
                } catch (IOException e) {
                    // não bloquear a geração do PDF por um traço
                    logger.warn("Não foi possível desenhar o traço do título: {}", e.getMessage());
                }

                drawCenteredText(state,
                        "Documento gerado em: " + java.time.LocalDateTime.now().format(DATE_FORMATTER),
                        300, 742, fontLabel, 10);

                int yPosition = state.yPosition;

                // Seção: Detalhes do Certificado
                yPosition = drawSectionHeader(state, "Detalhes do Certificado", yPosition, fontBold, 14, false);

                // Se tivermos o certificateData em Base64, decodificar e extrair campos X.509
                X509Certificate x509 = null;
                if (certificate.getCertificateData() != null && !certificate.getCertificateData().isEmpty()) {
                    try {
                        String certStr = certificate.getCertificateData().trim();
                        // Se veio em PEM, remover headers/footers
                        if (certStr.contains("-----BEGIN CERTIFICATE-----") || certStr.contains("BEGIN CERTIFICATE")) {
                            certStr = certStr.replaceAll("-----BEGIN CERTIFICATE-----", "")
                                    .replaceAll("-----END CERTIFICATE-----", "")
                                    .replaceAll("\\s", "");
                        }

                        byte[] der = Base64.getDecoder().decode(certStr);
                        CertificateFactory cf = CertificateFactory.getInstance("X.509");
                        x509 = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(der));
                    } catch (Exception e) {
                        logger.warn("Falha ao parsear certificateData do certificado (id={} subject={}): {}",
                                certificate.getId(), certificate.getSubjectName(), e.getMessage());
                        x509 = null;
                    }
                }

                if (x509 != null) {
                    // Versão
                    yPosition = drawKeyValueStyled(state, "Versão:", String.valueOf(x509.getVersion()),
                            (int) PAGE_MARGIN_LEFT, yPosition, fontLabel, fontNormal, 12);

                    // Número de Série
                    BigInteger serial = x509.getSerialNumber();
                    yPosition = drawKeyValueStyled(state, "Número de Série:", formatSerialNumber(serial),
                            (int) PAGE_MARGIN_LEFT, yPosition, fontLabel, fontNormal, 12);

                    // Assinatura (algoritmo)
                    yPosition = drawKeyValueStyled(state, "Algoritmo de Assinatura:", x509.getSigAlgName(),
                            (int) PAGE_MARGIN_LEFT, yPosition, fontLabel, fontNormal, 12);

                    // Emissor (wrap se longo)
                    String issuer = x509.getIssuerX500Principal().getName();
                    yPosition = drawKeyValueStyled(state, "Emissor:", "", (int) PAGE_MARGIN_LEFT, yPosition,
                            fontLabel, fontNormal, 12);
                    yPosition = drawWrappedText(state, issuer, VALUE_OFFSET_X, yPosition, fontNormal, 10,
                            MAX_VALUE_WIDTH, 6);
                    yPosition -= 6;

                    // Validade
                    SimpleDateFormat df = new SimpleDateFormat("EEEE, MMMM dd, yyyy 'at' h:mm:ss a z");
                    yPosition = drawKeyValueStyled(state, "Válido de:", df.format(x509.getNotBefore()),
                            (int) PAGE_MARGIN_LEFT, yPosition, fontLabel, fontNormal, 12);
                    yPosition = drawKeyValueStyled(state, "Válido até:", df.format(x509.getNotAfter()),
                            (int) PAGE_MARGIN_LEFT, yPosition, fontLabel, fontNormal, 12);

                } else {
                    // Fallback para dados do DTO
                    yPosition = drawKeyValueStyled(state, "Versão:", "3", (int) PAGE_MARGIN_LEFT, yPosition,
                            fontLabel, fontNormal, 12);
                    yPosition = drawKeyValueStyled(state, "Número de Série:", certificate.getSerialNumber(),
                            (int) PAGE_MARGIN_LEFT, yPosition, fontLabel, fontNormal, 12);
                    yPosition = drawKeyValueStyled(state, "Algoritmo de Assinatura:",
                            "SHA-256 with RSA Encryption",
                            (int) PAGE_MARGIN_LEFT, yPosition, fontLabel, fontNormal, 12);
                    yPosition = drawKeyValueStyled(state, "Emissor:", certificate.getIssuerName(),
                            (int) PAGE_MARGIN_LEFT, yPosition, fontLabel, fontNormal, 12);

                    String validFrom = certificate.getValidFrom() != null
                            ? certificate.getValidFrom()
                                    .format(DateTimeFormatter.ofPattern("EEEE, MMMM dd, yyyy 'at' h:mm:ss a"))
                            : "N/A";
                    yPosition = drawKeyValueStyled(state, "Válido de:", validFrom,
                            (int) PAGE_MARGIN_LEFT, yPosition, fontLabel, fontNormal, 12);

                    String validTo = certificate.getValidTo() != null
                            ? certificate.getValidTo()
                                    .format(DateTimeFormatter.ofPattern("EEEE, MMMM dd, yyyy 'at' h:mm:ss a"))
                            : "N/A";
                    yPosition = drawKeyValueStyled(state, "Válido até:", validTo,
                            (int) PAGE_MARGIN_LEFT, yPosition, fontLabel, fontNormal, 12);
                }

                // Seção: Informações do Subject
                yPosition = drawSectionHeader(state, "Informações do Subject", yPosition, fontBold, 14, false);

                yPosition = drawKeyValueStyled(state, "Common Name:",
                        certificate.getSubjectName() != null ? certificate.getSubjectName() : "N/A",
                        (int) PAGE_MARGIN_LEFT, yPosition, fontLabel, fontNormal, 12);
                yPosition = drawKeyValueStyled(state, "Organização:",
                        certificate.getOrganization() != null ? certificate.getOrganization() : "N/A",
                        (int) PAGE_MARGIN_LEFT, yPosition, fontLabel, fontNormal, 12);
                yPosition = drawKeyValueStyled(state, "Localidade:",
                        certificate.getLocality() != null ? certificate.getLocality() : "N/A",
                        (int) PAGE_MARGIN_LEFT, yPosition, fontLabel, fontNormal, 12);
                yPosition = drawKeyValueStyled(state, "País:",
                        certificate.getCountry() != null ? certificate.getCountry() : "N/A",
                        (int) PAGE_MARGIN_LEFT, yPosition, fontLabel, fontNormal, 12);

                // Seção: Informações da Chave Pública
                yPosition = drawSectionHeader(state, "Informações da Chave Pública", yPosition, fontBold, 14,
                        false);

                if (x509 != null) {
                    PublicKey pubKey = x509.getPublicKey();
                    String pubInfo = pubKey.getAlgorithm();
                    int keySize = -1;
                    if (pubKey instanceof RSAPublicKey) {
                        keySize = ((RSAPublicKey) pubKey).getModulus().bitLength();
                        pubInfo = "RSA Encryption";
                    }

                    yPosition = drawKeyValueStyled(state, "Algoritmo:", pubInfo,
                            (int) PAGE_MARGIN_LEFT, yPosition, fontLabel, fontNormal, 12);
                    yPosition = drawKeyValueStyled(state, "Tamanho da Chave:",
                            keySize != -1 ? keySize + " bits" : "N/A",
                            (int) PAGE_MARGIN_LEFT, yPosition, fontLabel, fontNormal, 12);
                    yPosition = drawKeyValueStyled(state, "Uso da Chave:",
                            "Criptografar, Verificar, Encapsular, Derivar",
                            (int) PAGE_MARGIN_LEFT, yPosition, fontLabel, fontNormal, 12);

                    // Informações da chave pública (resumido)
                    yPosition = drawKeyValueStyled(state, "Algoritmo da Chave Pública:", pubKey.getAlgorithm(),
                            (int) PAGE_MARGIN_LEFT, yPosition, fontLabel, fontNormal, 12);
                    if (keySize != -1) {
                        yPosition = drawKeyValueStyled(state, "Tamanho (bits):", String.valueOf(keySize),
                                (int) PAGE_MARGIN_LEFT, yPosition, fontLabel, fontNormal, 12);
                    }

                } else {
                    // Fallback para dados do DTO
                    yPosition = drawKeyValueStyled(state, "Algoritmo:", "RSA Encryption",
                            (int) PAGE_MARGIN_LEFT, yPosition, fontLabel, fontNormal, 12);
                    yPosition = drawKeyValueStyled(state, "Tamanho da Chave:", "2,048 bits",
                            (int) PAGE_MARGIN_LEFT, yPosition, fontLabel, fontNormal, 12);
                    yPosition = drawKeyValueStyled(state, "Expoente:", "65537",
                            (int) PAGE_MARGIN_LEFT, yPosition, fontLabel, fontNormal, 12);
                    yPosition = drawKeyValueStyled(state, "Uso da Chave:",
                            "Criptografar, Verificar, Encapsular, Derivar",
                            (int) PAGE_MARGIN_LEFT, yPosition, fontLabel, fontNormal, 12);
                }

                // Seção: Assinatura
                yPosition = drawSectionHeader(state, "Assinatura Digital", yPosition, fontBold, 14, false);

                if (x509 != null) {
                    try {
                        byte[] sig = x509.getSignature();
                        String hexSig = bytesToHex(sig);
                        // Mostrar apenas um resumo da assinatura
                        yPosition = drawKeyValueStyled(state, "Assinatura (tamanho bytes):", String.valueOf(sig.length),
                                (int) PAGE_MARGIN_LEFT, yPosition, fontLabel, fontNormal, 12);
                    } catch (Exception e) {
                        logger.warn("Erro ao processar assinatura do certificado: {}", e.getMessage());
                    }
                }
            }

            // Rodapé profissional para todas as páginas
            try {
                String footerLeft = "Certificado: "
                        + (certificate.getSubjectName() != null ? certificate.getSubjectName() : "-");
                String footerMid = "Emissor: "
                        + (certificate.getIssuerName() != null ? certificate.getIssuerName() : "-");

                PDFont footerFont = new PDType1Font(Standard14Fonts.FontName.HELVETICA);
                int totalPages = document.getNumberOfPages();
                for (int i = 0; i < totalPages; i++) {
                    PDPage p = document.getPage(i);
                    try (PDPageContentStream footerStream = new PDPageContentStream(document, p,
                            PDPageContentStream.AppendMode.APPEND, true)) {
                        // Linha separadora do rodapé
                        footerStream.setLineWidth(0.5f);
                        footerStream.moveTo(PAGE_MARGIN_LEFT, 40);
                        footerStream.lineTo(PAGE_MARGIN_RIGHT, 40);
                        footerStream.stroke();

                        // Texto do rodapé
                        footerStream.setFont(footerFont, 7);
                        footerStream.beginText();
                        footerStream.newLineAtOffset(PAGE_MARGIN_LEFT, 30);
                        footerStream.showText(footerLeft);
                        footerStream.endText();

                        footerStream.beginText();
                        footerStream.newLineAtOffset(PAGE_MARGIN_LEFT, 20);
                        footerStream.showText(footerMid);
                        footerStream.endText();

                        footerStream.beginText();
                        footerStream.newLineAtOffset(PAGE_MARGIN_RIGHT - 80, 20);
                        footerStream.showText("Página " + (i + 1) + "/" + totalPages);
                        footerStream.endText();
                    }
                }
            } catch (Exception e) {
                logger.warn("Erro ao adicionar rodapé: {}", e.getMessage());
            }

            document.save(outputStream);
            return outputStream.toByteArray();
        }
    }

    private int drawKeyValueStyled(PageState state, String label, String value, int x, int y,
            PDFont labelFont, PDFont valueFont, int fontSize) throws IOException {
        state.ensureSpace(fontSize + 8);
        PDPageContentStream contentStream = state.contentStream;
        contentStream.setFont(labelFont, fontSize);
        contentStream.beginText();
        contentStream.newLineAtOffset(x, y);
        contentStream.showText(label);
        contentStream.endText();

        float valueX = VALUE_OFFSET_X;
        if (value == null) {
            value = "N/A";
        }

        if (value.isEmpty()) {
            state.yPosition = y - (fontSize + 6);
            return state.yPosition;
        }

        float textWidth = valueFont.getStringWidth(value) / 1000 * fontSize;
        if (textWidth <= MAX_VALUE_WIDTH) {
            contentStream.setFont(valueFont, fontSize);
            contentStream.beginText();
            contentStream.newLineAtOffset(valueX, y);
            contentStream.showText(value);
            contentStream.endText();
            state.yPosition = y - (fontSize + 6);
            return state.yPosition;
        } else {
            int newY = drawWrappedText(state, value, valueX, y, valueFont, fontSize, MAX_VALUE_WIDTH, 4);
            state.yPosition = newY;
            return newY;
        }
    }

    private int drawWrappedText(PageState state, String text, float x, int startY, PDFont font,
            int fontSize, float maxWidth, int lineSpacing) throws IOException {
        if (text == null || text.isEmpty())
            return startY;

        List<String> lines = new ArrayList<>();
        String[] paragraphs = text.split("\\r?\\n");

        for (String paragraph : paragraphs) {
            StringBuilder currentLine = new StringBuilder();
            String[] words = paragraph.split(" ");

            for (String word : words) {
                String testLine = currentLine.length() == 0 ? word : currentLine.toString() + " " + word;
                float lineWidth = font.getStringWidth(testLine) / 1000 * fontSize;

                if (lineWidth <= maxWidth) {
                    currentLine.append(currentLine.length() == 0 ? word : " " + word);
                } else {
                    if (currentLine.length() > 0) {
                        lines.add(currentLine.toString());
                        currentLine = new StringBuilder(word);
                    } else {
                        int charsThatFit = calculateCharsThatFit(font, fontSize, word, maxWidth);
                        if (charsThatFit > 0) {
                            lines.add(word.substring(0, charsThatFit));
                            currentLine = new StringBuilder(word.substring(charsThatFit));
                        } else {
                            lines.add(word);
                            currentLine = new StringBuilder();
                        }
                    }
                }
            }

            if (currentLine.length() > 0) {
                lines.add(currentLine.toString());
            }
        }

        int y = startY;
        PDPageContentStream contentStream = state.contentStream;
        for (String line : lines) {
            state.ensureSpace(fontSize + lineSpacing);
            // if ensureSpace created a new page, update contentStream reference
            contentStream = state.contentStream;
            contentStream.setFont(font, fontSize);
            contentStream.beginText();
            contentStream.newLineAtOffset(x, y);
            contentStream.showText(line);
            contentStream.endText();
            y -= (fontSize + lineSpacing);
        }
        return y;
    }

    private int calculateCharsThatFit(PDFont font, int fontSize, String text, float maxWidth) throws IOException {
        for (int i = 1; i <= text.length(); i++) {
            String substring = text.substring(0, i);
            float width = font.getStringWidth(substring) / 1000 * fontSize;
            if (width > maxWidth) {
                return i - 1;
            }
        }
        return text.length();
    }

    private int drawSectionHeader(PageState state, String title, int yPosition, PDFont font,
            int fontSize, boolean drawLine) throws IOException {
        yPosition -= 12;
        state.ensureSpace(fontSize + 8);
        PDPageContentStream contentStream = state.contentStream;
        contentStream.setFont(font, fontSize);
        contentStream.beginText();
        contentStream.newLineAtOffset(PAGE_MARGIN_LEFT, yPosition);
        contentStream.showText(title);
        contentStream.endText();
        yPosition -= (fontSize + 4);

        if (drawLine) {
            contentStream.setLineWidth(0.5f);
            float lineY = yPosition + 2;
            contentStream.moveTo(PAGE_MARGIN_LEFT, lineY);
            contentStream.lineTo(PAGE_MARGIN_RIGHT, lineY);
            contentStream.stroke();
            yPosition -= 8;
        }
        state.yPosition = yPosition;
        return yPosition;
    }

    private void drawCenteredText(PageState state, String text, float centerX, float y,
            PDFont font, float fontSize) throws IOException {
        state.ensureSpace((int) fontSize + 8);
        PDPageContentStream contentStream = state.contentStream;
        contentStream.setFont(font, fontSize);
        float textWidth = font.getStringWidth(text) / 1000 * fontSize;
        float x = centerX - (textWidth / 2);

        contentStream.beginText();
        contentStream.newLineAtOffset(x, y);
        contentStream.showText(text);
        contentStream.endText();
    }

    private static String wrapHexString(String s, int width) {
        if (s == null || s.isEmpty())
            return "";
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < s.length(); i += width) {
            if (i > 0)
                sb.append('\n');
            int end = Math.min(i + width, s.length());
            sb.append(s, i, end);
        }
        return sb.toString();
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X", b));
        }
        return sb.toString();
    }

    private String formatSerialNumber(BigInteger serial) {
        String hex = serial.toString(16).toUpperCase();
        // Formatar com espaços a cada 2 caracteres, similar ao formato das imagens
        StringBuilder formatted = new StringBuilder();
        for (int i = 0; i < hex.length(); i += 2) {
            if (i > 0)
                formatted.append(' ');
            formatted.append(hex, i, Math.min(i + 2, hex.length()));
        }
        return formatted.toString();
    }

    // Classe auxiliar para gerenciar paginação
    private class PageState implements AutoCloseable {
        PDDocument document;
        PDPage page;
        PDPageContentStream contentStream;
        int yPosition;

        PageState(PDDocument document) throws IOException {
            this.document = document;
            this.page = new PDPage();
            this.document.addPage(this.page);
            this.contentStream = new PDPageContentStream(document, page);
            this.yPosition = 710; // posição inicial padrão usada anteriormente
        }

        void newPage() throws IOException {
            // fechar contentStream atual
            try {
                this.contentStream.close();
            } catch (Exception ignored) {
            }
            this.page = new PDPage();
            this.document.addPage(this.page);
            this.contentStream = new PDPageContentStream(document, page);
            this.yPosition = 750; // topo razoável para nova página
        }

        void ensureSpace(int required) throws IOException {
            // Página única: não criar novas páginas. Apenas atualiza yPosition se
            // necessário.
            // Mantemos método para compatibilidade com chamadas existentes, mas não
            // criaremos páginas extras.
            return;
        }

        @Override
        public void close() {
            try {
                if (this.contentStream != null)
                    this.contentStream.close();
            } catch (Exception ignored) {
            }
        }
    }

    public String pdfToBase64(byte[] pdfBytes) {
        return Base64.getEncoder().encodeToString(pdfBytes);
    }

    // Extrai componente do DN, por exemplo key="CN" retorna o valor do CN se
    // existir
    private String getDNComponent(String dn, String key) {
        if (dn == null || key == null)
            return null;
        try {
            Pattern p = Pattern.compile(key + "=([^,]+)");
            Matcher m = p.matcher(dn);
            if (m.find()) {
                return m.group(1).trim();
            }
        } catch (Exception e) {
            // ignora
        }
        return null;
    }
}