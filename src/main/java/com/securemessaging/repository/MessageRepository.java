package com.securemessaging.repository;

import com.securemessaging.model.Message;
import com.securemessaging.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

@Repository
public interface MessageRepository extends JpaRepository<Message, Long> {

        // Buscar conversa entre dois usuários
        @Query("SELECT m FROM Message m JOIN FETCH m.sender JOIN FETCH m.receiver " +
                        "WHERE (m.sender = :user1 AND m.receiver = :user2) OR (m.sender = :user2 AND m.receiver = :user1) "
                        +
                        "ORDER BY m.sentAt ASC")
        List<Message> findConversationBetween(@Param("user1") User user1, @Param("user2") User user2);

        // Buscar mensagens enviadas ou recebidas por um usuário
        List<Message> findBySenderOrReceiver(User sender, User receiver);

        // Buscar mensagens não recebidas
        List<Message> findByReceiverAndReceivedAtIsNull(User receiver);

        // Contar mensagens enviadas por um usuário
        long countBySender(User sender);

        // Contar mensagens recebidas por um usuário
        long countByReceiver(User receiver);

        // Buscar mensagens por status
        List<Message> findByStatus(Message.MessageStatus status);

        // Buscar mensagens por tipo
        List<Message> findByMessageType(Message.MessageType messageType);

        // Buscar mensagens não lidas por receptor
        @Query("SELECT m FROM Message m WHERE m.receiver = :receiver AND m.readAt IS NULL")
        List<Message> findUnreadMessagesByReceiver(@Param("receiver") User receiver);

        // Buscar mensagens enviadas após uma data
        List<Message> findBySenderAndSentAtAfter(User sender, LocalDateTime sentAt);

        // Buscar mensagens recebidas após uma data
        List<Message> findByReceiverAndReceivedAtAfter(User receiver, LocalDateTime receivedAt);

        // Buscar mensagens assinadas
        @Query("SELECT m FROM Message m WHERE m.signed = true")
        List<Message> findSignedMessages();

        // Buscar mensagens encriptadas
        @Query("SELECT m FROM Message m WHERE m.encrypted = true")
        List<Message> findEncryptedMessages();

        // Buscar mensagens por hash (para verificação de integridade)
        Optional<Message> findByMessageHash(String messageHash);

        // Contar mensagens não lidas
        @Query("SELECT COUNT(m) FROM Message m WHERE m.receiver = :receiver AND m.readAt IS NULL")
        long countUnreadMessagesByReceiver(@Param("receiver") User receiver);

        // Buscar últimas mensagens de cada conversa
        @Query("SELECT m FROM Message m WHERE m.id IN (" +
                        "SELECT MAX(m2.id) FROM Message m2 WHERE m2.sender = :user OR m2.receiver = :user " +
                        "GROUP BY CASE WHEN m2.sender = :user THEN m2.receiver.id ELSE m2.sender.id END)")
        List<Message> findLastMessagesFromEachConversation(@Param("user") User user);

        // Estatísticas de mensagens por período
        @Query("SELECT COUNT(m), m.messageType FROM Message m " +
                        "WHERE m.sentAt BETWEEN :startDate AND :endDate GROUP BY m.messageType")
        List<Object[]> countMessagesByTypeAndPeriod(@Param("startDate") LocalDateTime startDate,
                        @Param("endDate") LocalDateTime endDate);

        // ✅ MÉTODOS CORRIGIDOS PARA ESTATÍSTICAS
        @Query("SELECT COUNT(m) FROM Message m WHERE m.sender.id = :userId")
        long countBySenderId(@Param("userId") Long userId);

        @Query("SELECT COUNT(m) FROM Message m WHERE m.receiver.id = :userId")
        long countByReceiverId(@Param("userId") Long userId);

        @Query("SELECT COUNT(m) FROM Message m WHERE m.sender.id = :userId AND m.messageType = :messageType")
        long countBySenderIdAndMessageType(@Param("userId") Long userId,
                        @Param("messageType") Message.MessageType messageType);

        @Query("SELECT COUNT(m) FROM Message m WHERE m.sender.id = :userId AND m.encrypted = :encrypted")
        long countBySenderIdAndEncrypted(@Param("userId") Long userId, @Param("encrypted") boolean encrypted);

        @Query("SELECT COUNT(m) FROM Message m WHERE m.receiver.id = :userId AND m.messageType = :messageType")
        long countByReceiverIdAndMessageType(@Param("userId") Long userId,
                        @Param("messageType") Message.MessageType messageType);

        @Query("SELECT COUNT(m) FROM Message m WHERE m.receiver.id = :userId AND m.encrypted = :encrypted")
        long countByReceiverIdAndEncrypted(@Param("userId") Long userId, @Param("encrypted") boolean encrypted);
}