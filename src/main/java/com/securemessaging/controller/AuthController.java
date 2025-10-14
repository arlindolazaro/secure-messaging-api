package com.securemessaging.controller;

import com.securemessaging.dto.AuthRequest;
import com.securemessaging.dto.AuthResponse;
import com.securemessaging.dto.RegisterRequest;
import com.securemessaging.service.AuthService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/auth")
@CrossOrigin(origins = "*")
@Tag(name = "Authentication", description = "API para autenticação e registo de utilizadores")
public class AuthController {

    @Autowired
    private AuthService authService;

    @Operation(summary = "Autenticar utilizador", description = "Realiza login e retorna token JWT")
    @PostMapping("/login")
    public ResponseEntity<?> authenticateUser(@Valid @RequestBody AuthRequest authRequest) {
        try {
            AuthResponse response = authService.authenticateUser(
                    authRequest.getUsername(), authRequest.getPassword());
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(
                    Map.of("error", "Falha na autenticação", "message", e.getMessage()));
        }
    }

    @Operation(summary = "Registar novo utilizador", description = "Cria novo utilizador com geração automática de chaves RSA e Diffie-Hellman")
    @PostMapping("/register")
    public ResponseEntity<?> registerUser(@Valid @RequestBody RegisterRequest registerRequest) {
        try {
            AuthResponse response = authService.registerUser(registerRequest);
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(
                    Map.of("error", "Erro no registro", "message", e.getMessage()));
        }
    }

    @Operation(summary = "Verificar token", description = "Valida se o token JWT é válido")
    @PostMapping("/verify-token")
    public ResponseEntity<?> verifyToken(@RequestBody Map<String, String> request) {
        try {
            String token = request.get("token");
            if (token == null) {
                return ResponseEntity.badRequest().body(Map.of("valid", false, "error", "Token é obrigatório"));
            }

            boolean isValid = authService.validateToken(token);
            return ResponseEntity.ok(Map.of("valid", isValid));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of("valid", false, "error", e.getMessage()));
        }
    }

    @Operation(summary = "Refresh token", description = "Gera novo token JWT")
    @PostMapping("/refresh-token")
    public ResponseEntity<?> refreshToken(@RequestBody Map<String, String> request) {
        try {
            String oldToken = request.get("token");
            if (oldToken == null) {
                return ResponseEntity.badRequest().body(Map.of("error", "Token é obrigatório"));
            }

            AuthResponse response = authService.refreshToken(oldToken);
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    @Operation(summary = "Logout", description = "Invalidar token (em produção usar blacklist)")
    @PostMapping("/logout")
    public ResponseEntity<?> logout(@RequestBody Map<String, String> request) {
        try {
            String token = request.get("token");
            if (token != null) {
                authService.logout(token);
            }
            return ResponseEntity.ok(Map.of("success", true, "message", "Logout realizado com sucesso"));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    @Operation(summary = "Verificar disponibilidade", description = "Verifica se username e email estão disponíveis")
    @GetMapping("/check-availability")
    public ResponseEntity<?> checkAvailability(
            @RequestParam String username,
            @RequestParam String email) {
        try {
            Map<String, Boolean> availability = authService.checkAvailability(username, email);
            return ResponseEntity.ok(availability);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    @Operation(summary = "Health check", description = "Verifica se o serviço de autenticação está operacional")
    @GetMapping("/health")
    public ResponseEntity<?> healthCheck() {
        try {
            return ResponseEntity.ok(Map.of(
                    "status", "UP",
                    "service", "Authentication",
                    "timestamp", java.time.LocalDateTime.now()));
        } catch (Exception e) {
            return ResponseEntity.status(500).body(Map.of(
                    "status", "DOWN",
                    "error", e.getMessage()));
        }
    }
}