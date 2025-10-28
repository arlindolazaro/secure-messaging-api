package com.securemessaging.service;

import com.securemessaging.model.User;
import com.securemessaging.repository.KeyPairRepository;
import com.securemessaging.repository.UserRepository;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest
public class UserServiceIntegrationTest {

    @Autowired
    private UserService userService;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private KeyPairRepository keyPairRepository;

    @Test
    @Transactional
    public void whenCreateUser_thenKeyPairCreated() throws Exception {
        User user = new User();
        user.setUsername("test_integration_user");
        user.setEmail("test_integration@example.com");
        user.setPassword("password123");

        User saved = userService.createUser(user);
        assertNotNull(saved.getId(), "Saved user should have id");

        List<com.securemessaging.model.KeyPair> kps = keyPairRepository.findByUser(saved);
        assertNotNull(kps, "KeyPair list should not be null");
        assertFalse(kps.isEmpty(), "At least one KeyPair should be created for new user");

        // Opcional: verificar que a key pair possui algoritmo RSA
        assertEquals("RSA", kps.get(0).getAlgorithm());
    }
}
