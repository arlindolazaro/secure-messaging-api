package com.securemessaging.service;

import com.securemessaging.dto.MessageDTO;
import com.securemessaging.model.Message;
import com.securemessaging.model.User;
import com.securemessaging.repository.MessageRepository;
import com.securemessaging.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.messaging.simp.SimpMessagingTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.multipart.MultipartFile;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.time.LocalDateTime;
import java.util.Base64;
import java.util.List;
import java.util.stream.Collectors;

@Service
@Transactional
public class MessageService {

    @Autowired
    private MessageRepository messageRepository;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private CryptoService cryptoService;

    @Autowired
    private FileStorageService fileStorageService;

    @Autowired
    private DiffieHellmanService diffieHellmanService;

    @Autowired
    private UserService userService;

    @Autowired
    private SimpMessagingTemplate messagingTemplate;

    // No MessageService.java - Método corrigido
    @Transactional
    public MessageDTO sendEncryptedMessage(MessageDTO messageDTO) throws Exception {
        if (messageDTO.getSenderId() == null || messageDTO.getReceiverId() == null) {
            throw new IllegalArgumentException("SenderId e ReceiverId são obrigatórios");
        }

        User sender = userRepository.findById(messageDTO.getSenderId())
                .orElseThrow(() -> new IllegalArgumentException("Remetente não encontrado"));
        User receiver = userRepository.findById(messageDTO.getReceiverId())
                .orElseThrow(() -> new IllegalArgumentException("Destinatário não encontrado"));

        String finalContent;
        boolean isEncrypted = false;
        String messageHash = null;

        // ✅ LÓGICA CORRIGIDA: Sempre criptografar se o destinatário tiver chave pública
        if (receiver.getPublicKey() != null && messageDTO.getContent() != null) {
            PublicKey receiverPublicKey = cryptoService.stringToPublicKey(receiver.getPublicKey());
            finalContent = cryptoService.encryptPGPStyle(messageDTO.getContent(), receiverPublicKey);
            isEncrypted = true;
            messageHash = cryptoService.hashWithSHA256(messageDTO.getContent()); // Hash do original
            System.out.println("✅ Mensagem criptografada para o destinatário: " + receiver.getUsername());
        } else {
            finalContent = messageDTO.getContent();
            isEncrypted = false;
            if (messageDTO.getContent() != null) {
                messageHash = cryptoService.hashWithSHA256(messageDTO.getContent());
            }
            System.out.println("ℹ️ Mensagem enviada em texto normal");
        }

        Message message = new Message();
        message.setSender(sender);
        message.setReceiver(receiver);
        message.setContent(finalContent);
        message.setMessageType(Message.MessageType.TEXT);
        message.setEncrypted(isEncrypted);
        message.setMessageHash(messageHash);
        message.setSentAt(LocalDateTime.now());
        message.setStatus(Message.MessageStatus.SENT);

        // ✅ Assinatura digital (opcional)
        if (messageDTO.isSigned() && sender.getPrivateKey() != null && messageDTO.getContent() != null) {
            PrivateKey senderPrivateKey = cryptoService.stringToPrivateKey(sender.getPrivateKey());
            String signature = cryptoService.signData(messageDTO.getContent(), senderPrivateKey);
            message.setSignature(signature);
            message.setSigned(true);
            System.out.println("✅ Mensagem assinada digitalmente");
        }

        Message saved = messageRepository.save(message);
        MessageDTO savedDTO = convertToDTO(saved);

        notifyNewMessageViaWebSocket(savedDTO);
        return savedDTO;
    }

    @Transactional
    public MessageDTO sendMessageWithDH(Long senderId, Long receiverId, String content, String dhSessionId)
            throws Exception {
        User sender = userRepository.findById(senderId)
                .orElseThrow(() -> new IllegalArgumentException("Remetente não encontrado"));
        User receiver = userRepository.findById(receiverId)
                .orElseThrow(() -> new IllegalArgumentException("Destinatário não encontrado"));

        SecretKey aesKey = diffieHellmanService.getAESKeyForSession(dhSessionId);
        String encryptedContent = cryptoService.encryptWithAES(content, aesKey);
        String messageHash = cryptoService.hashWithSHA256(content);

        Message message = new Message();
        message.setSender(sender);
        message.setReceiver(receiver);
        message.setContent(encryptedContent);
        message.setMessageType(Message.MessageType.TEXT);
        message.setEncrypted(true);
        message.setMessageHash(messageHash);
        message.setDhSessionKey(dhSessionId);
        message.setSentAt(LocalDateTime.now());
        message.setStatus(Message.MessageStatus.SENT);

        Message saved = messageRepository.save(message);
        MessageDTO savedDTO = convertToDTO(saved);

        notifyNewMessageViaWebSocket(savedDTO);
        return savedDTO;
    }

    @Transactional
    public MessageDTO sendMessage(MessageDTO messageDTO) throws Exception {
        if (messageDTO.getSenderId() == null || messageDTO.getReceiverId() == null) {
            throw new IllegalArgumentException("SenderId e ReceiverId são obrigatórios");
        }

        User sender = userRepository.findById(messageDTO.getSenderId())
                .orElseThrow(() -> new IllegalArgumentException("Remetente não encontrado"));
        User receiver = userRepository.findById(messageDTO.getReceiverId())
                .orElseThrow(() -> new IllegalArgumentException("Destinatário não encontrado"));

        String messageHash = cryptoService.hashWithSHA256(messageDTO.getContent());

        Message message = new Message();
        message.setSender(sender);
        message.setReceiver(receiver);
        message.setContent(messageDTO.getContent());
        message.setMessageType(Message.MessageType.valueOf(
                messageDTO.getMessageType() != null ? messageDTO.getMessageType() : "TEXT"));
        message.setEncrypted(false);
        message.setMessageHash(messageHash);
        message.setSentAt(LocalDateTime.now());
        message.setStatus(Message.MessageStatus.SENT);

        if (messageDTO.isSigned() && sender.getPrivateKey() != null) {
            PrivateKey senderPrivateKey = cryptoService.stringToPrivateKey(sender.getPrivateKey());
            String signature = cryptoService.signData(messageDTO.getContent(), senderPrivateKey);
            message.setSignature(signature);
            message.setSigned(true);
        }

        Message saved = messageRepository.save(message);
        MessageDTO savedDTO = convertToDTO(saved);

        notifyNewMessageViaWebSocket(savedDTO);
        return savedDTO;
    }

    // No MessageService.java - Melhorar o método decryptMessage
    public String decryptMessage(Long messageId, Long userId) throws Exception {
        try {
            System.out.println("🎯 Iniciando decriptação - MessageId: " + messageId + ", UserId: " + userId);

            Message message = messageRepository.findById(messageId)
                    .orElseThrow(() -> new IllegalArgumentException("Mensagem não encontrada: " + messageId));

            // ✅ VERIFICAR SE É IMAGEM
            if (Message.MessageType.IMAGE.equals(message.getMessageType())) {
                throw new IllegalArgumentException("Use o endpoint de imagens para visualizar imagens");
            }

            if (!message.isEncrypted()) {
                System.out.println("ℹ️ Mensagem não está criptografada, retornando conteúdo original");
                return message.getContent();
            }

            // ✅ VERIFICAÇÕES DE SEGURANÇA
            if (message.getContent() == null || message.getContent().trim().isEmpty()) {
                throw new IllegalArgumentException("Conteúdo da mensagem está vazio");
            }

            // ✅ VERIFICAR PERMISSÕES
            if (!message.getSender().getId().equals(userId) && !message.getReceiver().getId().equals(userId)) {
                throw new SecurityException("Usuário não tem permissão para decriptar esta mensagem");
            }

            // ✅ OBTER CHAVE PRIVADA
            PrivateKey privateKey = getPrivateKey(userId);
            System.out.println("✅ Chave privada obtida com sucesso");

            // ✅ DECRIPTAÇÃO
            String decryptedContent = cryptoService.decryptPGPStyle(message.getContent(), privateKey);

            if (decryptedContent == null || decryptedContent.trim().isEmpty()) {
                throw new RuntimeException("Conteúdo decriptado está vazio");
            }

            System.out.println("✅ Conteúdo decriptado com sucesso - Tamanho: " + decryptedContent.length());

            // ✅ VERIFICAR INTEGRIDADE
            if (message.getMessageHash() != null) {
                String calculatedHash = cryptoService.hashWithSHA256(decryptedContent);
                if (!calculatedHash.equals(message.getMessageHash())) {
                    System.err.println("❌ Falha na verificação de integridade");
                    System.err.println("Hash esperado: " + message.getMessageHash());
                    System.err.println("Hash calculado: " + calculatedHash);
                    throw new SecurityException(
                            "Falha na verificação de integridade - mensagem pode ter sido alterada");
                }
                System.out.println("✅ Integridade verificada com sucesso");
            }

            return decryptedContent;

        } catch (Exception e) {
            System.err.println("💥 Erro crítico na decriptação: " + e.getMessage());
            e.printStackTrace();
            throw e; // Re-lançar para tratamento no controller
        }
    }

    private PrivateKey getPrivateKey(Long userId) throws Exception {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("Usuário não encontrado"));

        if (user.getPrivateKey() == null) {
            throw new RuntimeException("Usuário não possui chave privada");
        }

        String privateKeyStr = user.getPrivateKey();
        if (privateKeyStr == null || privateKeyStr.trim().isEmpty()) {
            throw new RuntimeException("Chave privada do usuário está vazia");
        }

        return cryptoService.stringToPrivateKey(privateKeyStr);
    }

    public String decryptMessage(Long messageId, Long userId, String userPassword) throws Exception {
        Message message = messageRepository.findById(messageId)
                .orElseThrow(() -> new IllegalArgumentException("Mensagem não encontrada"));

        if (!message.isEncrypted()) {
            return message.getContent();
        }

        PrivateKey privateKey = userService.getDecryptedPrivateKey(userId, userPassword);
        String decryptedContent = cryptoService.decryptPGPStyle(message.getContent(), privateKey);

        if (message.getMessageHash() != null) {
            String calculatedHash = cryptoService.hashWithSHA256(decryptedContent);
            if (!calculatedHash.equals(message.getMessageHash())) {
                throw new SecurityException("Falha na verificação de integridade");
            }
        }

        return decryptedContent;
    }

    public String decryptMessageWithDH(Long messageId, String dhSessionId) throws Exception {
        Message message = messageRepository.findById(messageId)
                .orElseThrow(() -> new IllegalArgumentException("Mensagem não encontrada"));

        if (!message.isEncrypted() || !dhSessionId.equals(message.getDhSessionKey())) {
            throw new IllegalArgumentException("Mensagem não compatível com a sessão DH");
        }

        SecretKey aesKey = diffieHellmanService.getAESKeyForSession(dhSessionId);
        String decryptedContent = cryptoService.decryptWithAES(message.getContent(), aesKey);

        String calculatedHash = cryptoService.hashWithSHA256(decryptedContent);
        if (!calculatedHash.equals(message.getMessageHash())) {
            throw new SecurityException("Falha na verificação de integridade");
        }

        return decryptedContent;
    }

    @Transactional
    public MessageDTO sendEncryptedImage(Long senderId, Long receiverId, MultipartFile imageFile, String clientFileHash)
            throws Exception {
        User sender = userRepository.findById(senderId)
                .orElseThrow(() -> new IllegalArgumentException("Remetente não encontrado"));
        User receiver = userRepository.findById(receiverId)
                .orElseThrow(() -> new IllegalArgumentException("Destinatário não encontrado"));

        if (!fileStorageService.isValidImageType(imageFile.getContentType())) {
            throw new IllegalArgumentException("Tipo de arquivo de imagem não suportado");
        }

        if (receiver.getPublicKey() == null) {
            throw new IllegalArgumentException("Destinatário não possui chave pública");
        }

        // ✅ CORREÇÃO: Usar armazenamento simples sem criptografia dupla
        String fileName = fileStorageService.storeFile(imageFile);
        byte[] fileBytes = imageFile.getBytes();

        // Criar chave AES apenas para criptografia da chave (não do arquivo)
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(128);
        SecretKey fileKey = keyGen.generateKey();

        // Encriptar chave AES com RSA do destinatário
        Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        PublicKey receiverPublicKey = cryptoService.stringToPublicKey(receiver.getPublicKey());
        rsaCipher.init(Cipher.ENCRYPT_MODE, receiverPublicKey);
        String encryptedFileKey = Base64.getEncoder().encodeToString(rsaCipher.doFinal(fileKey.getEncoded()));

        // ✅ HASH do arquivo original para integridade: usar hash do cliente se
        // fornecido, senão calcular aqui
        String fileHash;
        if (clientFileHash != null && !clientFileHash.trim().isEmpty()) {
            fileHash = clientFileHash;
        } else {
            fileHash = cryptoService.hashWithSHA256(fileBytes);
        }

        Message message = new Message();
        message.setSender(sender);
        message.setReceiver(receiver);
        message.setMessageType(Message.MessageType.IMAGE);
        message.setFileName(fileName);
        message.setFileType(imageFile.getContentType());
        message.setFileSize(imageFile.getSize());
        message.setFileHash(fileHash);
        message.setEncryptedSymmetricKey(encryptedFileKey);
        message.setEncrypted(true);
        message.setSentAt(LocalDateTime.now());
        message.setStatus(Message.MessageStatus.SENT);
        message.setContent(null);

        Message saved = messageRepository.save(message);
        MessageDTO savedDTO = convertToDTO(saved);

        notifyNewMessageViaWebSocket(savedDTO);
        return savedDTO;
    }

    public byte[] retrieveEncryptedImage(Long messageId, Long userId) throws Exception {
        Message message = messageRepository.findById(messageId)
                .orElseThrow(() -> new IllegalArgumentException("Mensagem não encontrada"));

        if (!Message.MessageType.IMAGE.equals(message.getMessageType())) {
            throw new IllegalArgumentException("Mensagem não é uma imagem");
        }

        User user = userRepository.findById(userId)
                .orElseThrow(() -> new IllegalArgumentException("Usuário não encontrado"));

        if (!message.getSender().getId().equals(userId) && !message.getReceiver().getId().equals(userId)) {
            throw new SecurityException("Acesso não autorizado a esta imagem");
        }

        if (message.getEncryptedSymmetricKey() == null) {
            java.nio.file.Path filePath = java.nio.file.Paths.get("uploads").resolve(message.getFileName());
            return java.nio.file.Files.readAllBytes(filePath);
        }

        PrivateKey privateKey = cryptoService.stringToPrivateKey(user.getPrivateKey());
        Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        rsaCipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decryptedKeyBytes = rsaCipher.doFinal(
                Base64.getDecoder().decode(message.getEncryptedSymmetricKey()));
        SecretKey fileKey = new SecretKeySpec(decryptedKeyBytes, "AES");

        java.nio.file.Path filePath = java.nio.file.Paths.get("uploads").resolve(message.getFileName());
        return java.nio.file.Files.readAllBytes(filePath);
    }

    @Transactional
    public MessageDTO signMessage(Long messageId, Long userId) throws Exception {
        Message message = messageRepository.findById(messageId)
                .orElseThrow(() -> new IllegalArgumentException("Mensagem não encontrada"));

        User user = userRepository.findById(userId)
                .orElseThrow(() -> new IllegalArgumentException("Usuário não encontrado"));

        if (user.getPrivateKey() == null) {
            throw new IllegalArgumentException("Usuário não possui chave privada para assinar");
        }

        PrivateKey privateKey = cryptoService.stringToPrivateKey(user.getPrivateKey());

        String contentToSign;
        if (message.isEncrypted()) {
            contentToSign = decryptMessage(messageId, userId);
        } else {
            contentToSign = message.getContent();
        }

        String signature = cryptoService.signData(contentToSign, privateKey);
        message.setSignature(signature);
        message.setSigned(true);

        Message saved = messageRepository.save(message);
        return convertToDTO(saved);
    }

    public boolean verifyMessageSignature(Long messageId, Long userId) throws Exception {
        Message message = messageRepository.findById(messageId)
                .orElseThrow(() -> new IllegalArgumentException("Mensagem não encontrada"));

        User user = userRepository.findById(userId)
                .orElseThrow(() -> new IllegalArgumentException("Usuário não encontrado"));

        if (!message.isSigned() || message.getSignature() == null) {
            return false;
        }

        if (user.getPublicKey() == null) {
            throw new IllegalArgumentException("Usuário não possui chave pública para verificação");
        }

        PublicKey publicKey = cryptoService.stringToPublicKey(user.getPublicKey());

        String contentToVerify;
        if (message.isEncrypted()) {
            contentToVerify = decryptMessage(messageId, userId);
        } else {
            contentToVerify = message.getContent();
        }

        return cryptoService.verifySignature(contentToVerify, message.getSignature(), publicKey);
    }

    public boolean verifyMessageIntegrity(Long messageId) throws Exception {
        Message message = messageRepository.findById(messageId)
                .orElseThrow(() -> new IllegalArgumentException("Mensagem não encontrada"));

        if (message.getMessageHash() == null) {
            return false;
        }

        if (message.isEncrypted()) {
            return true;
        }

        String calculatedHash = cryptoService.hashWithSHA256(message.getContent());
        boolean integrityValid = calculatedHash.equals(message.getMessageHash());

        if (integrityValid) {
            message.setVerified(true);
            messageRepository.save(message);
        }

        return integrityValid;
    }

    @Transactional(readOnly = true)
    public List<MessageDTO> getAllMessages() {
        return messageRepository.findAll().stream()
                .map(this::convertToDTO)
                .collect(Collectors.toList());
    }

    @Transactional(readOnly = true)
    public List<MessageDTO> getMessagesByUser(Long userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new IllegalArgumentException("Usuário não encontrado"));
        return messageRepository.findBySenderOrReceiver(user, user).stream()
                .map(this::convertToDTO)
                .collect(Collectors.toList());
    }

    @Transactional(readOnly = true)
    public List<MessageDTO> getConversation(Long userId1, Long userId2) {
        User user1 = userRepository.findById(userId1)
                .orElseThrow(() -> new RuntimeException("Usuário 1 não encontrado: " + userId1));
        User user2 = userRepository.findById(userId2)
                .orElseThrow(() -> new RuntimeException("Usuário 2 não encontrado: " + userId2));
        return messageRepository.findConversationBetween(user1, user2).stream()
                .map(this::convertToDTO)
                .collect(Collectors.toList());
    }

    @Transactional(readOnly = true)
    public List<MessageDTO> getUnreadMessages(Long userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new IllegalArgumentException("Usuário não encontrado"));
        return messageRepository.findUnreadMessagesByReceiver(user).stream()
                .map(this::convertToDTO)
                .collect(Collectors.toList());
    }

    public MessageDTO getMessageById(Long messageId) {
        Message message = messageRepository.findById(messageId)
                .orElseThrow(() -> new IllegalArgumentException("Mensagem não encontrada"));
        return convertToDTO(message);
    }

    @Transactional
    public void markAsReceived(Long messageId) {
        Message msg = messageRepository.findById(messageId)
                .orElseThrow(() -> new IllegalArgumentException("Mensagem não encontrada"));
        msg.setReceivedAt(LocalDateTime.now());
        if (msg.getStatus() == Message.MessageStatus.SENT) {
            msg.setStatus(Message.MessageStatus.DELIVERED);
        }
        messageRepository.save(msg);
    }

    @Transactional
    public void markAsRead(Long messageId) {
        Message msg = messageRepository.findById(messageId)
                .orElseThrow(() -> new IllegalArgumentException("Mensagem não encontrada"));
        msg.setReadAt(LocalDateTime.now());
        if (msg.getStatus() == Message.MessageStatus.DELIVERED) {
            msg.setStatus(Message.MessageStatus.READ);
        }
        messageRepository.save(msg);
    }

    @Transactional
    public boolean deleteMessage(Long messageId) {
        try {
            if (messageRepository.existsById(messageId)) {
                messageRepository.deleteById(messageId);
                return true;
            }
            return false;
        } catch (Exception e) {
            throw new RuntimeException("Erro ao deletar mensagem: " + e.getMessage());
        }
    }

    @Transactional(readOnly = true)
    public long countMessagesByUser(Long userId) {
        try {
            User user = userRepository.findById(userId)
                    .orElseThrow(() -> new IllegalArgumentException("Usuário não encontrado"));
            return messageRepository.countBySender(user);
        } catch (Exception e) {
            return 0;
        }
    }

    public String calculateFileHash(byte[] fileBytes) throws Exception {
        if (fileBytes == null || fileBytes.length == 0) {
            throw new IllegalArgumentException("Arquivo vazio ou inválido para cálculo de hash");
        }
        return cryptoService.hashWithSHA256(fileBytes);
    }

    private MessageDTO convertToDTO(Message msg) {
        MessageDTO dto = new MessageDTO();
        dto.setId(msg.getId());
        dto.setContent(msg.getContent());
        dto.setMessageType(msg.getMessageType() != null ? msg.getMessageType().toString() : "TEXT");
        dto.setSenderId(msg.getSender() != null ? msg.getSender().getId() : null);
        dto.setSenderUsername(msg.getSender() != null ? msg.getSender().getUsername() : null);
        dto.setReceiverId(msg.getReceiver() != null ? msg.getReceiver().getId() : null);
        dto.setReceiverUsername(msg.getReceiver() != null ? msg.getReceiver().getUsername() : null);
        dto.setEncrypted(msg.isEncrypted());
        dto.setSigned(msg.isSigned());
        dto.setVerified(msg.isVerified());
        dto.setEncryptedSymmetricKey(msg.getEncryptedSymmetricKey());
        dto.setIv(msg.getIv());
        dto.setSignature(msg.getSignature());
        dto.setMessageHash(msg.getMessageHash());
        dto.setDhSessionKey(msg.getDhSessionKey());
        dto.setFileName(msg.getFileName());
        dto.setFileType(msg.getFileType());
        dto.setFileSize(msg.getFileSize());
        dto.setFileHash(msg.getFileHash());
        dto.setStatus(msg.getStatus() != null ? msg.getStatus().toString() : "SENT");
        dto.setSentAt(msg.getSentAt());
        dto.setReceivedAt(msg.getReceivedAt());
        dto.setReadAt(msg.getReadAt());
        return dto;
    }

    private void notifyNewMessageViaWebSocket(MessageDTO messageDTO) {
        try {
            String senderDestination = "/topic/user/" + messageDTO.getSenderId() + "/messages";
            messagingTemplate.convertAndSend(senderDestination, messageDTO);

            String receiverDestination = "/topic/user/" + messageDTO.getReceiverId() + "/messages";
            messagingTemplate.convertAndSend(receiverDestination, messageDTO);

            // Também enviar para a fila de usuário (destination /user/queue/messages)
            // usando o username como principal, para garantir entrega a sessões
            // específicas do usuário (ex.: múltiplas abas). O broker irá rotear
            // para as sessões assinantes de /user/queue/messages.
            try {
                if (messageDTO.getReceiverUsername() != null) {
                    messagingTemplate.convertAndSendToUser(
                            messageDTO.getReceiverUsername(),
                            "/queue/messages",
                            messageDTO);
                }

                if (messageDTO.getSenderUsername() != null) {
                    messagingTemplate.convertAndSendToUser(
                            messageDTO.getSenderUsername(),
                            "/queue/messages",
                            messageDTO);
                }
            } catch (Exception ex) {
                System.err.println("Aviso: falha ao enviar convertAndSendToUser: " + ex.getMessage());
            }
        } catch (Exception e) {
            System.err.println("Erro ao enviar notificação WebSocket: " + e.getMessage());
        }
    }
}