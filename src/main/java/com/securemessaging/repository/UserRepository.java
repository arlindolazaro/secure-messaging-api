package com.securemessaging.repository;

import com.securemessaging.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {

    Optional<User> findByUsername(String username);

    Optional<User> findByEmail(String email);

    boolean existsByUsername(String username);

    boolean existsByEmail(String email);

    @Query("SELECT u FROM User u WHERE u.enabled = true")
    List<User> findActiveUsers();

    @Query("SELECT u FROM User u WHERE u.publicKey IS NOT NULL")
    List<User> findUsersWithPublicKey();

    @Query("SELECT u FROM User u WHERE u.lastLogin >= :sinceDate")
    List<User> findUsersWithRecentLogin(@Param("sinceDate") LocalDateTime sinceDate);

    @Query("SELECT u FROM User u LEFT JOIN FETCH u.certificates WHERE u.id = :userId")
    Optional<User> findByIdWithCertificates(@Param("userId") Long userId);

    @Query("SELECT u FROM User u LEFT JOIN FETCH u.keyPairs WHERE u.id = :userId")
    Optional<User> findByIdWithKeyPairs(@Param("userId") Long userId);

    @Query("SELECT u FROM User u LEFT JOIN FETCH u.sentMessages LEFT JOIN FETCH u.receivedMessages WHERE u.id = :userId")
    Optional<User> findByIdWithMessages(@Param("userId") Long userId);

    @Query("SELECT u FROM User u WHERE u.username = :usernameOrEmail OR u.email = :usernameOrEmail")
    Optional<User> findByUsernameOrEmail(@Param("usernameOrEmail") String usernameOrEmail);

    @Query("SELECT COUNT(u) FROM User u WHERE u.enabled = true")
    long countActiveUsers();

    List<User> findByCreatedAtAfter(LocalDateTime createdAt);
}