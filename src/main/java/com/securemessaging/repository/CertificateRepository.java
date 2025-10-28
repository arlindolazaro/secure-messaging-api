package com.securemessaging.repository;

import com.securemessaging.model.Certificate;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

@Repository
public interface CertificateRepository extends JpaRepository<Certificate, Long> {

    // Buscar certificados por usuário
    List<Certificate> findByUserId(Long userId);

    // Buscar por nome do subject
    List<Certificate> findBySubjectName(String subjectName);

    // Buscar por emissor
    @Query("SELECT c FROM Certificate c WHERE c.issuerName = :issuerName")
    List<Certificate> findByIssuerName(@Param("issuerName") String issuerName);

    // Buscar certificados válidos (não revogados e não expirados)
    @Query("SELECT c FROM Certificate c WHERE c.status = 'VALID'")
    List<Certificate> findValidCertificates();

    // Buscar certificados activos por usuário
    @Query("SELECT c FROM Certificate c WHERE c.user.id = :userId AND c.status = 'VALID'")
    List<Certificate> findActiveCertificatesByUser(@Param("userId") Long userId);

    // Buscar Root CAs de um usuário específico
    @Query("SELECT c FROM Certificate c WHERE c.user.id = :userId AND c.isRootCA = true")
    List<Certificate> findRootCertificatesByUser(@Param("userId") Long userId);

    // Buscar todos os Root CAs
    @Query("SELECT c FROM Certificate c WHERE c.isRootCA = true")
    List<Certificate> findAllRootCertificates();

    // Buscar certificado válido do usuário
    @Query("SELECT c FROM Certificate c WHERE c.user.id = :userId AND c.status = 'VALID' AND c.validTo > CURRENT_TIMESTAMP")
    Optional<Certificate> findValidCertificateByUser(@Param("userId") Long userId);

    // Buscar por usuário e emissor
    @Query("SELECT c FROM Certificate c WHERE c.user.id = :userId AND c.issuerName = :issuerName")
    List<Certificate> findByUserIdAndIssuerName(@Param("userId") Long userId, @Param("issuerName") String issuerName);

    // ✅ NOVO: Buscar certificados expirados
    @Query("SELECT c FROM Certificate c WHERE c.validTo < CURRENT_TIMESTAMP AND c.status = 'VALID'")
    List<Certificate> findExpiredCertificates();

    // ✅ NOVO: Buscar certificados por status
    List<Certificate> findByStatus(Certificate.CertificateStatus status);

    // ✅ NOVO: Buscar certificados que expiram em breve
    @Query("SELECT c FROM Certificate c WHERE c.validTo BETWEEN :startDate AND :endDate AND c.status = 'VALID'")
    List<Certificate> findCertificatesExpiringBetween(@Param("startDate") LocalDateTime startDate,
            @Param("endDate") LocalDateTime endDate);

    // ✅ NOVO: Buscar por número de série
    Optional<Certificate> findBySerialNumber(String serialNumber);

    // ✅ NOVO: Verificar se existe certificado válido para o usuário
    @Query("SELECT COUNT(c) > 0 FROM Certificate c WHERE c.user.id = :userId AND c.status = 'VALID' AND c.validTo > CURRENT_TIMESTAMP")
    boolean existsValidCertificateByUser(@Param("userId") Long userId);
}