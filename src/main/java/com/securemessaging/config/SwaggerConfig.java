package com.securemessaging.config;

import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.info.Contact;
import io.swagger.v3.oas.models.info.License;
import io.swagger.v3.oas.models.security.SecurityScheme;
import io.swagger.v3.oas.models.security.SecurityRequirement;
import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.servers.Server;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.List;

@Configuration
public class SwaggerConfig {

        @Bean
        public OpenAPI customOpenAPI() {
                return new OpenAPI()
                                .info(new Info()
                                                .title("Secure Messaging API")
                                                .version("1.0")
                                                .description("""
                                                                Sistema de Mensagens Seguras - Criado por Arlindo Lázaro Cau Júnior

                                                                **Funcionalidades Principais:**
                                                                - ✅ Criptografia RSA 1024 bits
                                                                - ✅ Diffie-Hellman para acordo de chaves
                                                                - ✅ Funções Hash SHA-256/SHA3 para integridade
                                                                - ✅ Protocolo PGP (RSA + AES) para mensagens
                                                                - ✅ PKI com certificados autoassinados
                                                                - ✅ WebSocket para comunicação em tempo real

                                                                **Tecnologias:**
                                                                - Spring Boot 3, Spring Security, JWT
                                                                - Bouncy Castle para criptografia
                                                                - WebSocket STOMP
                                                                - Swagger/OpenAPI 3
                                                                """)
                                                .contact(new Contact()
                                                                .name("Equipe Secure Messaging")
                                                                .email("arlindolazaro202@gmail.com"))
                                                .license(new License()
                                                                .name("MIT License")
                                                                .url("https://opensource.org/licenses/MIT")))
                                .servers(List.of(
                                                new Server()
                                                                .url("http://localhost:8080")
                                                                .description("Servidor de Desenvolvimento Local"),
                                                new Server()
                                                                .url("https://api.securemessaging.com")
                                                                .description("Servidor de Produção")))
                                .addSecurityItem(new SecurityRequirement().addList("JWT"))
                                .components(new Components()
                                                .addSecuritySchemes("JWT",
                                                                new SecurityScheme()
                                                                                .name("Authorization")
                                                                                .type(SecurityScheme.Type.HTTP)
                                                                                .scheme("bearer")
                                                                                .bearerFormat("JWT")
                                                                                .description("Insira o token JWT no formato: Bearer {token}")));
        }
}