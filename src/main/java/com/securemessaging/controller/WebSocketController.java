package com.securemessaging.controller;

import com.securemessaging.dto.MessageDTO;
import com.securemessaging.service.MessageService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.messaging.handler.annotation.MessageMapping;
import org.springframework.messaging.handler.annotation.Payload;
import org.springframework.messaging.simp.SimpMessagingTemplate;
import org.springframework.stereotype.Controller;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;

@Controller
public class WebSocketController {

    @Autowired
    private SimpMessagingTemplate messagingTemplate;

    @Autowired
    private MessageService messageService;

    /**
     * ✅ ENVIA MENSAGEM VIA WEBSOCKET - VERSÃO CORRIGIDA
     */
    // No WebSocketController.java - Método corrigido
    @MessageMapping("/chat.sendMessage")
    public void sendMessage(@Payload Map<String, Object> messageData) {
        try {
            System.out.println("📨 Recebendo mensagem via WebSocket: " + messageData);

            // ✅ EXTRAIR DADOS BÁSICOS
            Long senderId = Long.valueOf(messageData.get("senderId").toString());
            Long receiverId = Long.valueOf(messageData.get("receiverId").toString());
            String content = (String) messageData.get("content");
            Boolean signed = Boolean.valueOf(messageData.getOrDefault("signed", "false").toString());

            // ✅ CRIAR DTO SIMPLES - BACKEND DECIDE CRIPTOGRAFIA
            MessageDTO messageDTO = new MessageDTO();
            messageDTO.setSenderId(senderId);
            messageDTO.setReceiverId(receiverId);
            messageDTO.setContent(content);
            messageDTO.setSigned(signed);
            messageDTO.setMessageType("TEXT");

            // ✅ DELEGAR AO SERVICE (que decide automaticamente sobre criptografia)
            MessageDTO savedMessage = messageService.sendEncryptedMessage(messageDTO);

            System.out.println("✅ Mensagem processada pelo backend - ID: " + savedMessage.getId());

            // ✅ NOTIFICAR AMBAS AS PARTES
            String senderDestination = "/topic/user/" + savedMessage.getSenderId() + "/messages";
            String receiverDestination = "/topic/user/" + savedMessage.getReceiverId() + "/messages";

            messagingTemplate.convertAndSend(senderDestination, savedMessage);
            messagingTemplate.convertAndSend(receiverDestination, savedMessage);

            System.out.println("✅ Mensagem distribuída via WebSocket - ID: " + savedMessage.getId());

        } catch (Exception e) {
            System.err.println("❌ Erro ao processar mensagem WebSocket: " + e.getMessage());
            e.printStackTrace();

            // ✅ ENVIAR ERRO PARA O REMETENTE
            try {
                Long senderId = Long.valueOf(messageData.get("senderId").toString());
                String errorDestination = "/topic/user/" + senderId + "/errors";

                Map<String, Object> errorResponse = new HashMap<>();
                errorResponse.put("type", "MESSAGE_ERROR");
                errorResponse.put("error", true);
                errorResponse.put("message", "Falha ao enviar mensagem: " + e.getMessage());
                errorResponse.put("timestamp", LocalDateTime.now().toString());

                messagingTemplate.convertAndSend(errorDestination, errorResponse);
            } catch (Exception ex) {
                System.err.println("❌ Erro ao enviar mensagem de erro: " + ex.getMessage());
            }
        }
    }

    /**
     * ✅ DECRIPTA MENSAGEM VIA WEBSOCKET
     */
    @MessageMapping("/chat.decryptMessage")
    public void decryptMessage(@Payload Map<String, Object> decryptData) {
        try {
            Long messageId = Long.valueOf(decryptData.get("messageId").toString());
            Long userId = Long.valueOf(decryptData.get("userId").toString());

            System.out.println(
                    "🔓 Solicitando decriptação via WebSocket - MessageId: " + messageId + ", UserId: " + userId);

            // ✅ DECRIPTAR MENSAGEM
            String decryptedContent = messageService.decryptMessage(messageId, userId);

            // ✅ CRIAR EVENTO DE DECRIPTAÇÃO
            MessageDecryptedEvent event = new MessageDecryptedEvent();
            event.setMessageId(messageId);
            event.setUserId(userId);
            event.setDecryptedContent(decryptedContent);

            // ✅ NOTIFICAR USUÁRIO
            String destination = "/topic/user/" + userId + "/messageDecrypted";
            messagingTemplate.convertAndSend(destination, event);

            System.out.println("✅ Mensagem decriptada notificada - MessageId: " + messageId);

        } catch (Exception e) {
            System.err.println("❌ Erro ao decriptar mensagem via WebSocket: " + e.getMessage());

            // ✅ ENVIAR ERRO DE DECRIPTAÇÃO
            try {
                Long userId = Long.valueOf(decryptData.get("userId").toString());
                String errorDestination = "/topic/user/" + userId + "/errors";

                Map<String, Object> errorResponse = new HashMap<>();
                errorResponse.put("type", "DECRYPT_ERROR");
                errorResponse.put("error", true);
                errorResponse.put("message", "Falha ao decriptar mensagem: " + e.getMessage());
                errorResponse.put("timestamp", LocalDateTime.now().toString());

                messagingTemplate.convertAndSend(errorDestination, errorResponse);
            } catch (Exception ex) {
                System.err.println("❌ Erro ao enviar erro de decriptação: " + ex.getMessage());
            }
        }
    }

    /**
     * ✅ Indicador de digitação (typing)
     */
    @MessageMapping("/chat.typing")
    public void handleTyping(@Payload Map<String, Object> typingData) {
        try {
            Long senderId = Long.valueOf(typingData.get("senderId").toString());
            Long receiverId = Long.valueOf(typingData.get("receiverId").toString());
            Boolean typing = Boolean.valueOf(typingData.get("typing").toString());

            Map<String, Object> typingMessage = new HashMap<>();
            typingMessage.put("type", "TYPING_INDICATOR");
            typingMessage.put("senderId", senderId);
            typingMessage.put("typing", typing);
            typingMessage.put("timestamp", LocalDateTime.now().toString());

            messagingTemplate.convertAndSendToUser(
                    receiverId.toString(),
                    "/queue/typing",
                    typingMessage);

            System.out.println(
                    "✍️ Indicador de digitação - De: " + senderId + " Para: " + receiverId + " - Digitando: " + typing);
        } catch (Exception e) {
            System.err.println("❌ Erro ao processar indicador de digitação: " + e.getMessage());
        }
    }

    /**
     * ✅ Confirmação de leitura de mensagens
     */
    @MessageMapping("/chat.messageRead")
    public void handleMessageRead(@Payload Map<String, Object> readData) {
        try {
            Long messageId = Long.valueOf(readData.get("messageId").toString());
            Long readerId = Long.valueOf(readData.get("readerId").toString());

            messageService.markAsRead(messageId);

            MessageDTO message = messageService.getMessageById(messageId);

            if (message != null && message.getSenderId() != null) {
                Map<String, Object> readConfirmation = new HashMap<>();
                readConfirmation.put("type", "MESSAGE_READ");
                readConfirmation.put("messageId", messageId);
                readConfirmation.put("readerId", readerId);
                readConfirmation.put("readAt", LocalDateTime.now().toString());

                messagingTemplate.convertAndSendToUser(
                        message.getSenderId().toString(),
                        "/queue/messages",
                        readConfirmation);

                System.out.println("👀 Mensagem lida - ID: " + messageId + " por: " + readerId);
            }
        } catch (Exception e) {
            System.err.println("❌ Erro ao processar confirmação de leitura: " + e.getMessage());
        }
    }

    /**
     * ✅ Notifica quando usuário está online/offline
     */
    @MessageMapping("/chat.userStatus")
    public void userStatus(@Payload UserStatusEvent event) {
        try {
            String destination = "/topic/user/" + event.getUserId() + "/status";
            messagingTemplate.convertAndSend(destination, event);
            System.out.println(
                    "🟢 Status do usuário atualizado: " + event.getUsername() + " - Online: " + event.isOnline());
        } catch (Exception e) {
            System.err.println("❌ Erro ao atualizar status do usuário: " + e.getMessage());
        }
    }

    /**
     * ✅ VERIFICA ASSINATURA VIA WEBSOCKET
     */
    @MessageMapping("/chat.verifySignature")
    public void verifySignature(@Payload Map<String, Object> verifyData) {
        try {
            Long messageId = Long.valueOf(verifyData.get("messageId").toString());
            Long userId = Long.valueOf(verifyData.get("userId").toString());

            System.out.println("🔏 Verificando assinatura - MessageId: " + messageId + ", UserId: " + userId);

            boolean isValid = messageService.verifyMessageSignature(messageId, userId);

            Map<String, Object> result = new HashMap<>();
            result.put("type", "SIGNATURE_VERIFIED");
            result.put("messageId", messageId);
            result.put("valid", isValid);
            result.put("timestamp", LocalDateTime.now().toString());

            String destination = "/topic/user/" + userId + "/signature";
            messagingTemplate.convertAndSend(destination, result);

            System.out.println("✅ Assinatura verificada - MessageId: " + messageId + ", Válida: " + isValid);

        } catch (Exception e) {
            System.err.println("❌ Erro ao verificar assinatura: " + e.getMessage());
        }
    }

    /**
     * ✅ MENSAGEM DE TESTE DE CONEXÃO
     */
    @MessageMapping("/chat.ping")
    public void handlePing(@Payload Map<String, Object> pingData) {
        try {
            Long userId = Long.valueOf(pingData.get("userId").toString());

            Map<String, Object> pongResponse = new HashMap<>();
            pongResponse.put("type", "PONG");
            pongResponse.put("timestamp", LocalDateTime.now().toString());
            pongResponse.put("serverTime", System.currentTimeMillis());

            String destination = "/topic/user/" + userId + "/connection";
            messagingTemplate.convertAndSend(destination, pongResponse);

            System.out.println("🏓 Pong enviado para usuário: " + userId);
        } catch (Exception e) {
            System.err.println("❌ Erro ao processar ping: " + e.getMessage());
        }
    }

    // ===============================
    // 📦 CLASSES AUXILIARES DE EVENTO
    // ===============================

    public static class MessageDecryptedEvent {
        private Long messageId;
        private Long userId;
        private String decryptedContent;

        // Getters e Setters
        public Long getMessageId() {
            return messageId;
        }

        public void setMessageId(Long messageId) {
            this.messageId = messageId;
        }

        public Long getUserId() {
            return userId;
        }

        public void setUserId(Long userId) {
            this.userId = userId;
        }

        public String getDecryptedContent() {
            return decryptedContent;
        }

        public void setDecryptedContent(String decryptedContent) {
            this.decryptedContent = decryptedContent;
        }
    }

    public static class UserStatusEvent {
        private Long userId;
        private String username;
        private boolean online;

        // Getters e Setters
        public Long getUserId() {
            return userId;
        }

        public void setUserId(Long userId) {
            this.userId = userId;
        }

        public String getUsername() {
            return username;
        }

        public void setUsername(String username) {
            this.username = username;
        }

        public boolean isOnline() {
            return online;
        }

        public void setOnline(boolean online) {
            this.online = online;
        }
    }

    /**
     * ✅ CLASSE PARA RESPOSTAS DE ERRO PADRÃO
     */
    public static class ErrorResponse {
        private String type;
        private boolean error;
        private String message;
        private String timestamp;

        public ErrorResponse(String type, String message) {
            this.type = type;
            this.error = true;
            this.message = message;
            this.timestamp = LocalDateTime.now().toString();
        }

        // Getters e Setters
        public String getType() {
            return type;
        }

        public void setType(String type) {
            this.type = type;
        }

        public boolean isError() {
            return error;
        }

        public void setError(boolean error) {
            this.error = error;
        }

        public String getMessage() {
            return message;
        }

        public void setMessage(String message) {
            this.message = message;
        }

        public String getTimestamp() {
            return timestamp;
        }

        public void setTimestamp(String timestamp) {
            this.timestamp = timestamp;
        }
    }
}