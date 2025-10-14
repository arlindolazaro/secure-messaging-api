package com.securemessaging.repository;

import com.securemessaging.model.CertificateSigningRequest;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface CSRRepository extends JpaRepository<CertificateSigningRequest, Long> {

    List<CertificateSigningRequest> findByUserId(Long userId);

    List<CertificateSigningRequest> findByStatus(CertificateSigningRequest.CSRStatus status);

    @Query("SELECT csr FROM CertificateSigningRequest csr WHERE csr.user.id = :userId AND csr.status = 'PENDING'")
    List<CertificateSigningRequest> findPendingByUser(@Param("userId") Long userId);

    Optional<CertificateSigningRequest> findByIdAndUserId(Long id, Long userId);

    @Query("SELECT COUNT(csr) FROM CertificateSigningRequest csr WHERE csr.user.id = :userId AND csr.status = 'PENDING'")
    long countPendingByUser(@Param("userId") Long userId);
}