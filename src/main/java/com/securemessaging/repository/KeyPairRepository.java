package com.securemessaging.repository;

import com.securemessaging.model.KeyPair;
import com.securemessaging.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

@Repository
public interface KeyPairRepository extends JpaRepository<KeyPair, Long> {

    // Buscar todos os key pairs de um usuário
    List<KeyPair> findByUser(User user);

    // Buscar por usuário e algoritmo
    Optional<KeyPair> findByUserAndAlgorithm(User user, String algorithm);

    // ✅ NOVO: Buscar por usuário e tipo de chave
    List<KeyPair> findByUserAndKeyType(User user, KeyPair.KeyType keyType);

    // ✅ NOVO: Buscar chaves ativas por usuário
    @Query("SELECT kp FROM KeyPair kp WHERE kp.user = :user AND kp.active = true")
    List<KeyPair> findActiveKeyPairsByUser(@Param("user") User user);

    // ✅ NOVO: Buscar chave de encriptação ativa do usuário
    @Query("SELECT kp FROM KeyPair kp WHERE kp.user = :user AND kp.keyType = 'ENCRYPTION' AND kp.active = true")
    Optional<KeyPair> findActiveEncryptionKeyPair(@Param("user") User user);

    // ✅ NOVO: Buscar chave de assinatura ativa do usuário
    @Query("SELECT kp FROM KeyPair kp WHERE kp.user = :user AND kp.keyType = 'SIGNATURE' AND kp.active = true")
    Optional<KeyPair> findActiveSignatureKeyPair(@Param("user") User user);

    // ✅ NOVO: Buscar chaves expiradas
    @Query("SELECT kp FROM KeyPair kp WHERE kp.expiresAt < CURRENT_TIMESTAMP AND kp.active = true")
    List<KeyPair> findExpiredKeyPairs();

    // ✅ NOVO: Buscar chaves que expiram em breve
    @Query("SELECT kp FROM KeyPair kp WHERE kp.expiresAt BETWEEN :startDate AND :endDate AND kp.active = true")
    List<KeyPair> findKeyPairsExpiringBetween(@Param("startDate") LocalDateTime startDate,
            @Param("endDate") LocalDateTime endDate);

    // ✅ NOVO: Buscar por algoritmo e tamanho específico
    List<KeyPair> findByAlgorithmAndKeySize(String algorithm, int keySize);

    // ✅ NOVO: Contar chaves ativas por usuário
    @Query("SELECT COUNT(kp) FROM KeyPair kp WHERE kp.user = :user AND kp.active = true")
    long countActiveKeyPairsByUser(@Param("user") User user);
}