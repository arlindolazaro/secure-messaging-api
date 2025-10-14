package com.securemessaging.service;

import com.securemessaging.dto.AuthResponse;
import com.securemessaging.dto.RegisterRequest;
import com.securemessaging.model.User;
import com.securemessaging.security.JwtTokenProvider;

import java.util.HashMap;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

@Service
public class AuthService {

    @Autowired
    private UserService userService;

    @Autowired
    private JwtTokenProvider jwtTokenProvider;

    @Autowired
    private AuthenticationManager authenticationManager;

    // ✅ REGISTO DE UTILIZADOR COM GERAÇÃO AUTOMÁTICA DE CHAVES
    public AuthResponse registerUser(RegisterRequest registerRequest) {
        if (userService.existsByUsername(registerRequest.getUsername())) {
            throw new RuntimeException("Username já existe");
        }
        if (userService.existsByEmail(registerRequest.getEmail())) {
            throw new RuntimeException("Email já cadastrado");
        }

        // Validar força da password
        if (registerRequest.getPassword().length() < 8) {
            throw new RuntimeException("Password deve ter pelo menos 8 caracteres");
        }

        User user = new User();
        user.setUsername(registerRequest.getUsername());
        user.setEmail(registerRequest.getEmail());
        user.setPassword(registerRequest.getPassword());

        // ✅ CRIAÇÃO DE UTILIZADOR COM CHAVES RSA E DIFFIE-HELLMAN
        User savedUser = userService.createUser(user);

        // Atualizar último login
        userService.updateLastLogin(savedUser.getId());

        String token = jwtTokenProvider.generateToken(savedUser.getUsername());

        return new AuthResponse(
                token,
                savedUser.getUsername(),
                savedUser.getEmail(),
                savedUser.getId(),
                savedUser.getPublicKey() != null,
                savedUser.getDhPublicKey() != null);
    }

    // ✅ AUTENTICAÇÃO COM VERIFICAÇÃO DE CREDENCIAIS
    public AuthResponse authenticateUser(String username, String password) {
        User user = userService.findByUsername(username)
                .orElseThrow(() -> new RuntimeException("Usuário não encontrado"));

        if (!user.isEnabled()) {
            throw new RuntimeException("Conta desativada");
        }

        // Autenticar com Spring Security
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(username, password));

        SecurityContextHolder.getContext().setAuthentication(authentication);

        // Atualizar último login
        userService.updateLastLogin(user.getId());

        String token = jwtTokenProvider.generateToken(username);

        return new AuthResponse(
                token,
                user.getUsername(),
                user.getEmail(),
                user.getId(),
                user.getPublicKey() != null,
                user.getDhPublicKey() != null);
    }

    // ✅ VERIFICAÇÃO DE TOKEN
    public boolean validateToken(String token) {
        return jwtTokenProvider.validateToken(token);
    }

    // ✅ REFRESH DE TOKEN
    public AuthResponse refreshToken(String oldToken) {
        if (!jwtTokenProvider.validateToken(oldToken)) {
            throw new RuntimeException("Token inválido");
        }

        String username = jwtTokenProvider.getUsernameFromToken(oldToken);
        User user = userService.findByUsername(username)
                .orElseThrow(() -> new RuntimeException("Usuário não encontrado"));

        String newToken = jwtTokenProvider.generateToken(username);

        return new AuthResponse(
                newToken,
                user.getUsername(),
                user.getEmail(),
                user.getId(),
                user.getPublicKey() != null,
                user.getDhPublicKey() != null);
    }

    // ✅ LOGOUT - Em uma implementação real, invalidaríamos o token
    public void logout(String token) {
        // Em produção, adicionar token à blacklist
        System.out.println("Logout realizado para token: " + token.substring(0, 20) + "...");
    }

    // ✅ VERIFICAÇÃO DE DISPONIBILIDADE
    public Map<String, Boolean> checkAvailability(String username, String email) {
        Map<String, Boolean> availability = new HashMap<>();
        availability.put("usernameAvailable", !userService.existsByUsername(username));
        availability.put("emailAvailable", !userService.existsByEmail(email));
        return availability;
    }
}