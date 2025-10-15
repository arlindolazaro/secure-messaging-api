package com.securemessaging.controller;

import com.securemessaging.dto.MessageDTO;
import com.securemessaging.service.MessageService;
import com.securemessaging.service.UserService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/messages")
@Tag(name = "Messages", description = "API para envio e gestão de mensagens seguras com PGP e Diffie-Hellman")
@CrossOrigin(origins = "*")
public class MessageController {

    @Autowired
    private MessageService messageService;

    @Autowired
    private UserService userService;

    // ==================== ENVIO DE MENSAGENS ====================

    @Operation(summary = "Enviar mensagem encriptada PGP", description = "Envia mensagem com criptografia PGP automática (RSA + AES) e SHA-256")
    @PostMapping("/send/encrypted")
    public ResponseEntity<?> sendEncryptedMessage(@RequestBody MessageDTO messageDTO) {
        try {
            System.out.println("📨 Recebendo mensagem para envio criptografado: " + messageDTO);

            // ✅ VALIDAÇÃO EXPLÍCITA E DETALHADA
            if (messageDTO.getSenderId() == null) {
                return ResponseEntity.badRequest().body(Map.of(
                        "success", false,
                        "error", "senderId é obrigatório",
                        "field", "senderId",
                        "code", "MISSING_SENDER_ID"));
            }

            if (messageDTO.getReceiverId() == null) {
                return ResponseEntity.badRequest().body(Map.of(
                        "success", false,
                        "error", "receiverId é obrigatório",
                        "field", "receiverId",
                        "code", "MISSING_RECEIVER_ID"));
            }

            if (messageDTO.getContent() == null || messageDTO.getContent().trim().isEmpty()) {
                return ResponseEntity.badRequest().body(Map.of(
                        "success", false,
                        "error", "content é obrigatório",
                        "field", "content",
                        "code", "MISSING_CONTENT"));
            }

            // ✅ GARANTIR QUE O TIPO DE MENSAGEM ESTÁ DEFINIDO
            if (messageDTO.getMessageType() == null) {
                messageDTO.setMessageType("TEXT");
            }

            System.out.println("✅ Dados validados - Processando mensagem...");

            // ✅ DELEGAR PARA O SERVICE (decide automaticamente sobre criptografia)
            MessageDTO sentMessage = messageService.sendEncryptedMessage(messageDTO);

            System.out.println("✅ Mensagem processada com sucesso - ID: " + sentMessage.getId());

            return ResponseEntity.ok(Map.of(
                    "success", true,
                    "message", "Mensagem processada com sucesso",
                    "data", sentMessage));

        } catch (Exception e) {
            System.err.println("❌ Erro ao processar mensagem: " + e.getMessage());
            e.printStackTrace();

            return ResponseEntity.badRequest().body(Map.of(
                    "success", false,
                    "error", e.getMessage(),
                    "code", "PROCESSING_ERROR"));
        }
    }

    @Operation(summary = "Enviar mensagem com Diffie-Hellman", description = "Envia mensagem usando chave de sessão DH")
    @PostMapping("/send/dh")
    public ResponseEntity<?> sendMessageWithDH(@RequestBody Map<String, Object> request) {
        try {
            Long senderId = Long.valueOf(request.get("senderId").toString());
            Long receiverId = Long.valueOf(request.get("receiverId").toString());
            String content = (String) request.get("content");
            String dhSessionId = (String) request.get("dhSessionId");

            MessageDTO sentMessage = messageService.sendMessageWithDH(senderId, receiverId, content, dhSessionId);
            return ResponseEntity.ok(Map.of(
                    "success", true,
                    "message", "Mensagem DH enviada com sucesso",
                    "data", sentMessage));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of(
                    "success", false,
                    "error", e.getMessage()));
        }
    }

    @Operation(summary = "Enviar mensagem simples", description = "Envia mensagem sem criptografia (apenas com hash SHA-256)")
    @PostMapping("/send")
    public ResponseEntity<?> sendMessage(@RequestBody MessageDTO messageDTO) {
        try {
            MessageDTO sentMessage = messageService.sendMessage(messageDTO);
            return ResponseEntity.ok(Map.of(
                    "success", true,
                    "message", "Mensagem enviada com sucesso",
                    "data", sentMessage));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of(
                    "success", false,
                    "error", e.getMessage()));
        }
    }

    // ==================== DECRIPTAÇÃO DE MENSAGENS ====================

    @Operation(summary = "Descriptografar mensagem PGP", description = "Descriptografa mensagem PGP usando chave privada")
    @PostMapping("/{messageId}/decrypt")
    public ResponseEntity<?> decryptMessage(
            @PathVariable Long messageId,
            @RequestBody Map<String, Object> request) {
        try {
            Long userId = extractUserId(request);

            System.out
                    .println("🎯 Recebida requisição de decriptação - MessageId: " + messageId + ", UserId: " + userId);
            System.out.println("📦 Request body: " + request);

            // ✅ VALIDAÇÃO DE PERMISSÕES
            if (userId == null) {
                return ResponseEntity.badRequest().body(Map.of(
                        "success", false,
                        "error", "userId é obrigatório",
                        "code", "MISSING_USER_ID"));
            }

            String decryptedContent = messageService.decryptMessage(messageId, userId);

            System.out.println("✅ Decriptação concluída com sucesso para messageId: " + messageId);

            return ResponseEntity.ok(Map.of(
                    "success", true,
                    "decryptedContent", decryptedContent,
                    "messageId", messageId,
                    "userId", userId));

        } catch (Exception e) {
            System.err.println("❌ Erro na decriptação: " + e.getMessage());
            e.printStackTrace();

            return ResponseEntity.badRequest().body(Map.of(
                    "success", false,
                    "error", e.getMessage(),
                    "message", "Falha na decriptação da mensagem",
                    "timestamp", java.time.LocalDateTime.now()));
        }
    }

    @Operation(summary = "Descriptografar mensagem PGP com password", description = "Descriptografa mensagem PGP com verificação de password")
    @PostMapping("/{messageId}/decrypt/secure")
    public ResponseEntity<?> decryptMessageSecure(
            @PathVariable Long messageId,
            @RequestBody Map<String, Object> request) {
        try {
            Long userId = extractUserId(request);
            String password = (String) request.get("password");

            if (password == null) {
                return ResponseEntity.badRequest().body(Map.of(
                        "success", false,
                        "error", "Password é obrigatória para decriptação segura"));
            }

            String decryptedContent = messageService.decryptMessage(messageId, userId, password);

            return ResponseEntity.ok(Map.of(
                    "success", true,
                    "decryptedContent", decryptedContent,
                    "messageId", messageId,
                    "userId", userId));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of(
                    "success", false,
                    "error", e.getMessage()));
        }
    }

    @Operation(summary = "Descriptografar mensagem DH", description = "Descriptografa mensagem usando sessão Diffie-Hellman")
    @PostMapping("/{messageId}/decrypt/dh")
    public ResponseEntity<?> decryptMessageWithDH(
            @PathVariable Long messageId,
            @RequestBody Map<String, String> request) {
        try {
            String dhSessionId = request.get("dhSessionId");
            String decryptedContent = messageService.decryptMessageWithDH(messageId, dhSessionId);

            return ResponseEntity.ok(Map.of(
                    "success", true,
                    "decryptedContent", decryptedContent,
                    "messageId", messageId));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of(
                    "success", false,
                    "error", e.getMessage()));
        }
    }

    // ==================== ASSINATURAS DIGITAIS ====================

    @Operation(summary = "Assinar mensagem", description = "Assina mensagem digitalmente com chave privada RSA")
    @PostMapping("/{messageId}/sign")
    public ResponseEntity<?> signMessage(
            @PathVariable Long messageId,
            @RequestBody Map<String, Long> request) {
        try {
            Long userId = request.get("userId");
            MessageDTO signedMessage = messageService.signMessage(messageId, userId);

            return ResponseEntity.ok(Map.of(
                    "success", true,
                    "message", "Mensagem assinada com sucesso",
                    "data", signedMessage));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of(
                    "success", false,
                    "error", e.getMessage()));
        }
    }

    @Operation(summary = "Verificar assinatura", description = "Verifica assinatura digital da mensagem")
    @GetMapping("/{messageId}/verify-signature")
    public ResponseEntity<?> verifyMessageSignature(
            @PathVariable Long messageId,
            @RequestParam Long userId) {
        try {
            boolean isValid = messageService.verifyMessageSignature(messageId, userId);

            return ResponseEntity.ok(Map.of(
                    "success", true,
                    "signatureValid", isValid,
                    "message", isValid ? "Assinatura válida" : "Assinatura inválida"));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of(
                    "success", false,
                    "error", e.getMessage()));
        }
    }

    // ==================== VERIFICAÇÃO DE INTEGRIDADE ====================

    @Operation(summary = "Verificar integridade", description = "Verifica integridade da mensagem com SHA-256")
    @GetMapping("/{messageId}/verify-integrity")
    public ResponseEntity<?> verifyMessageIntegrity(@PathVariable Long messageId) {
        try {
            boolean integrityValid = messageService.verifyMessageIntegrity(messageId);

            return ResponseEntity.ok(Map.of(
                    "success", true,
                    "integrityValid", integrityValid,
                    "message", integrityValid ? "Integridade verificada" : "Falha na verificação de integridade"));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of(
                    "success", false,
                    "error", e.getMessage()));
        }
    }

    // ==================== CONSULTA DE MENSAGENS ====================

    @Operation(summary = "Obter conversa", description = "Obtém conversa completa entre dois utilizadores")
    @GetMapping("/conversation/{userId1}/{userId2}")
    public ResponseEntity<?> getConversationBetween(
            @PathVariable Long userId1,
            @PathVariable Long userId2) {
        try {
            List<MessageDTO> conversation = messageService.getConversation(userId1, userId2);
            return ResponseEntity.ok(Map.of(
                    "success", true,
                    "conversation", conversation,
                    "count", conversation.size()));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of(
                    "success", false,
                    "error", e.getMessage()));
        }
    }

    @Operation(summary = "Obter todas as mensagens")
    @GetMapping
    public ResponseEntity<?> getAllMessages() {
        try {
            List<MessageDTO> messages = messageService.getAllMessages();
            return ResponseEntity.ok(Map.of(
                    "success", true,
                    "messages", messages,
                    "count", messages.size()));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of(
                    "success", false,
                    "error", e.getMessage()));
        }
    }

    @Operation(summary = "Mensagens do utilizador")
    @GetMapping("/user/{userId}")
    public ResponseEntity<?> getMessagesByUser(@PathVariable Long userId) {
        try {
            List<MessageDTO> messages = messageService.getMessagesByUser(userId);
            return ResponseEntity.ok(Map.of(
                    "success", true,
                    "messages", messages,
                    "count", messages.size()));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of(
                    "success", false,
                    "error", e.getMessage()));
        }
    }

    @Operation(summary = "Mensagens não lidas")
    @GetMapping("/user/{userId}/unread")
    public ResponseEntity<?> getUnreadMessages(@PathVariable Long userId) {
        try {
            List<MessageDTO> unreadMessages = messageService.getUnreadMessages(userId);
            return ResponseEntity.ok(Map.of(
                    "success", true,
                    "unreadMessages", unreadMessages,
                    "count", unreadMessages.size()));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of(
                    "success", false,
                    "error", e.getMessage()));
        }
    }

    @Operation(summary = "Buscar mensagem por ID")
    @GetMapping("/{messageId}")
    public ResponseEntity<?> getMessageById(@PathVariable Long messageId) {
        try {
            MessageDTO message = messageService.getMessageById(messageId);
            return ResponseEntity.ok(Map.of(
                    "success", true,
                    "message", message));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of(
                    "success", false,
                    "error", e.getMessage()));
        }
    }

    // ==================== ATUALIZAÇÃO DE ESTADO ====================

    @Operation(summary = "Marcar como recebida")
    @PutMapping("/{messageId}/received")
    public ResponseEntity<?> markAsReceived(@PathVariable Long messageId) {
        try {
            messageService.markAsReceived(messageId);
            return ResponseEntity.ok(Map.of(
                    "success", true,
                    "message", "Mensagem marcada como recebida"));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of(
                    "success", false,
                    "error", e.getMessage()));
        }
    }

    @Operation(summary = "Marcar como lida")
    @PutMapping("/{messageId}/read")
    public ResponseEntity<?> markAsRead(@PathVariable Long messageId) {
        try {
            messageService.markAsRead(messageId);
            return ResponseEntity.ok(Map.of(
                    "success", true,
                    "message", "Mensagem marcada como lida"));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of(
                    "success", false,
                    "error", e.getMessage()));
        }
    }

    // ==================== DELEÇÃO ====================

    @Operation(summary = "Deletar mensagem")
    @DeleteMapping("/{messageId}")
    public ResponseEntity<?> deleteMessage(@PathVariable Long messageId) {
        try {
            boolean deleted = messageService.deleteMessage(messageId);
            return ResponseEntity.ok(Map.of(
                    "success", deleted,
                    "message", deleted ? "Mensagem deletada com sucesso" : "Mensagem não encontrada"));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of(
                    "success", false,
                    "error", e.getMessage()));
        }
    }

    // ==================== ESTATÍSTICAS ====================

    @Operation(summary = "Estatísticas de mensagens")
    @GetMapping("/user/{userId}/statistics")
    public ResponseEntity<?> getMessageStatistics(@PathVariable Long userId) {
        try {
            long totalMessages = messageService.countMessagesByUser(userId);
            List<MessageDTO> unreadMessages = messageService.getUnreadMessages(userId);

            return ResponseEntity.ok(Map.of(
                    "success", true,
                    "userId", userId,
                    "totalMessages", totalMessages,
                    "unreadCount", unreadMessages.size(),
                    "statistics", Map.of(
                            "total", totalMessages,
                            "unread", unreadMessages.size(),
                            "read", totalMessages - unreadMessages.size())));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of(
                    "success", false,
                    "error", e.getMessage()));
        }
    }

    @Operation(summary = "Health check")
    @GetMapping("/health")
    public ResponseEntity<?> healthCheck() {
        try {
            List<MessageDTO> messages = messageService.getAllMessages();
            long totalCount = messages.size();

            return ResponseEntity.ok(Map.of(
                    "status", "UP",
                    "service", "Messaging",
                    "totalMessages", totalCount,
                    "timestamp", java.time.LocalDateTime.now()));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of(
                    "status", "DOWN",
                    "error", e.getMessage()));
        }
    }

    // ==================== MÉTODOS AUXILIARES ====================

    private Long extractUserId(Map<String, Object> request) {
        if (request.get("userId") instanceof Long) {
            return (Long) request.get("userId");
        } else if (request.get("userId") instanceof Integer) {
            return ((Integer) request.get("userId")).longValue();
        } else if (request.get("userId") instanceof String) {
            try {
                return Long.parseLong((String) request.get("userId"));
            } catch (NumberFormatException e) {
                throw new IllegalArgumentException("Formato de userId inválido: " + request.get("userId"));
            }
        } else {
            throw new IllegalArgumentException("userId é obrigatório no corpo da requisição");
        }
    }

    private Long getAuthenticatedUserId() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication != null && authentication.isAuthenticated()) {
            String username = authentication.getName();

            var user = userService.findByUsername(username)
                    .orElseThrow(() -> new RuntimeException("Usuário não encontrado: " + username));

            System.out.println("✅ Usuário autenticado: " + username + " | ID: " + user.getId());
            return user.getId();
        }
        throw new RuntimeException("Usuário não autenticado");
    }
}