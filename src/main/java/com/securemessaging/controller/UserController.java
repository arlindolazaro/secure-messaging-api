package com.securemessaging.controller;

import com.securemessaging.dto.UserDTO;
import com.securemessaging.dto.UserSettingsDTO;
import jakarta.validation.Valid;
import com.securemessaging.service.UserService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/users")
@CrossOrigin(origins = "*")
@Tag(name = "User Management", description = "API para gestão de utilizadores")
public class UserController {

    @Autowired
    private UserService userService;

    @Operation(summary = "Obter todos os utilizadores")
    @GetMapping
    public ResponseEntity<?> getAllUsers() {
        try {
            List<UserDTO> users = userService.getAllUsers();
            return ResponseEntity.ok(Map.of(
                    "success", true,
                    "users", users,
                    "count", users.size()));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of(
                    "success", false,
                    "error", e.getMessage()));
        }
    }

    @Operation(summary = "Buscar utilizador por ID")
    @GetMapping("/{userId}")
    public ResponseEntity<?> getUserById(@PathVariable Long userId) {
        try {
            UserDTO user = userService.findById(userId)
                    .map(u -> new UserDTO(u.getId(), u.getUsername(), u.getEmail(), u.getPublicKey()))
                    .orElse(null);

            if (user != null) {
                return ResponseEntity.ok(Map.of(
                        "success", true,
                        "user", user));
            } else {
                return ResponseEntity.status(404).body(Map.of(
                        "success", false,
                        "error", "Utilizador não encontrado"));
            }
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of(
                    "success", false,
                    "error", e.getMessage()));
        }
    }

    @Operation(summary = "Obter chave pública do utilizador")
    @GetMapping("/{userId}/public-key")
    public ResponseEntity<?> getUserPublicKey(@PathVariable Long userId) {
        try {
            String publicKey = userService.getUserPublicKey(userId);
            return ResponseEntity.ok(Map.of(
                    "success", true,
                    "publicKey", publicKey,
                    "userId", userId));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of(
                    "success", false,
                    "error", e.getMessage()));
        }
    }

    @Operation(summary = "Obter chave pública DH do utilizador")
    @GetMapping("/{userId}/dh-public-key")
    public ResponseEntity<?> getUserDHPublicKey(@PathVariable Long userId) {
        try {
            String dhPublicKey = userService.getUserDHPublicKey(userId);
            return ResponseEntity.ok(Map.of(
                    "success", true,
                    "dhPublicKey", dhPublicKey,
                    "userId", userId));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of(
                    "success", false,
                    "error", e.getMessage()));
        }
    }

    @Operation(summary = "Configurar Diffie-Hellman", description = "Configura parâmetros DH para o utilizador")
    @PostMapping("/{userId}/setup-dh")
    public ResponseEntity<?> setupUserDiffieHellman(@PathVariable Long userId) {
        try {
            userService.setupUserDiffieHellman(userId);
            return ResponseEntity.ok(Map.of(
                    "success", true,
                    "message", "Diffie-Hellman configurado com sucesso",
                    "userId", userId));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of(
                    "success", false,
                    "error", e.getMessage()));
        }
    }

    @Operation(summary = "Realizar acordo de chaves DH", description = "Realiza acordo de chaves entre dois utilizadores")
    @PostMapping("/{userId1}/key-exchange/{userId2}")
    public ResponseEntity<?> performKeyExchange(@PathVariable Long userId1, @PathVariable Long userId2) {
        try {
            Map<String, Object> result = userService.performDiffieHellmanKeyExchange(userId1, userId2);
            return ResponseEntity.ok(Map.of(
                    "success", true,
                    "keyExchange", result));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of(
                    "success", false,
                    "error", e.getMessage()));
        }
    }

    @Operation(summary = "Exportar chaves do utilizador", description = "Exporta todas as chaves do utilizador (requer password)")
    @PostMapping("/{userId}/export-keys")
    public ResponseEntity<?> exportUserKeys(@PathVariable Long userId, @RequestBody Map<String, String> request) {
        try {
            String password = request.get("password");
            if (password == null) {
                return ResponseEntity.badRequest().body(Map.of(
                        "success", false,
                        "error", "Password é obrigatória"));
            }

            Map<String, Object> keys = userService.exportUserKeys(userId, password);
            return ResponseEntity.ok(Map.of(
                    "success", true,
                    "exportedKeys", keys));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of(
                    "success", false,
                    "error", e.getMessage()));
        }
    }

    @Operation(summary = "Atualizar password", description = "Atualiza password e reencripta chave privada")
    @PutMapping("/{userId}/password")
    public ResponseEntity<?> updatePassword(@PathVariable Long userId, @RequestBody Map<String, String> request) {
        try {
            String newPassword = request.get("newPassword");
            if (newPassword == null || newPassword.length() < 8) {
                return ResponseEntity.badRequest().body(Map.of(
                        "success", false,
                        "error", "Nova password deve ter pelo menos 8 caracteres"));
            }

            userService.updatePassword(userId, newPassword);
            return ResponseEntity.ok(Map.of(
                    "success", true,
                    "message", "Password atualizada com sucesso"));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of(
                    "success", false,
                    "error", e.getMessage()));
        }
    }

    @Operation(summary = "Estatísticas do utilizador")
    @GetMapping("/{userId}/statistics")
    public ResponseEntity<?> getUserStatistics(@PathVariable Long userId) {
        try {
            Map<String, Object> stats = userService.getUserStatistics(userId);
            return ResponseEntity.ok(Map.of(
                    "success", true,
                    "statistics", stats));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of(
                    "success", false,
                    "error", e.getMessage()));
        }
    }

    @Operation(summary = "Obter definições do utilizador")
    @GetMapping("/{userId}/settings")
    public ResponseEntity<?> getUserSettings(@PathVariable Long userId) {
        try {
            String settings = userService.getUserSettings(userId);
            return ResponseEntity.ok(Map.of(
                    "success", true,
                    "settings", settings));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of(
                    "success", false,
                    "error", e.getMessage()));
        }
    }

    @Operation(summary = "Atualizar definições do utilizador")
    @PutMapping("/{userId}/settings")
    public ResponseEntity<?> updateUserSettings(@PathVariable Long userId, @Valid @RequestBody UserSettingsDTO dto) {
        try {
            // basic validation passed, save raw JSON string
            userService.updateUserSettings(userId, dto.getSettingsJson());
            return ResponseEntity.ok(Map.of(
                    "success", true,
                    "message", "Definições atualizadas"));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of(
                    "success", false,
                    "error", e.getMessage()));
        }
    }

    @Operation(summary = "Eliminar conta do utilizador")
    @DeleteMapping("/{userId}")
    public ResponseEntity<?> deleteUser(@PathVariable Long userId) {
        try {
            userService.deleteUser(userId);
            return ResponseEntity.ok(Map.of("success", true, "message", "Utilizador eliminado"));
        } catch (Exception e) {
            return ResponseEntity.status(400).body(Map.of("success", false, "error", e.getMessage()));
        }
    }

    @Operation(summary = "Health check")
    @GetMapping("/health")
    public ResponseEntity<?> healthCheck() {
        try {
            long totalUsers = userService.getTotalUserCount();
            long activeUsers = userService.getActiveUserCount();

            return ResponseEntity.ok(Map.of(
                    "status", "UP",
                    "service", "User Management",
                    "totalUsers", totalUsers,
                    "activeUsers", activeUsers,
                    "timestamp", java.time.LocalDateTime.now()));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of(
                    "status", "DOWN",
                    "error", e.getMessage()));
        }
    }
}