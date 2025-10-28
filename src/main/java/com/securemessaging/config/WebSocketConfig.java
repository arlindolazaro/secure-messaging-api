package com.securemessaging.config;

import com.securemessaging.security.JwtTokenProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.messaging.simp.config.ChannelRegistration;
import org.springframework.messaging.simp.config.MessageBrokerRegistry;
import org.springframework.messaging.support.ChannelInterceptor;
import org.springframework.web.socket.config.annotation.EnableWebSocketMessageBroker;
import org.springframework.web.socket.config.annotation.StompEndpointRegistry;
import org.springframework.web.socket.config.annotation.WebSocketMessageBrokerConfigurer;

@Configuration
@EnableWebSocketMessageBroker
public class WebSocketConfig implements WebSocketMessageBrokerConfigurer {

        @Autowired
        private JwtTokenProvider jwtTokenProvider;

        @Override
        public void configureMessageBroker(MessageBrokerRegistry config) {
                config.enableSimpleBroker("/topic", "/queue");
                config.setApplicationDestinationPrefixes("/app");
                config.setUserDestinationPrefix("/user");
        }

        @Override
        public void registerStompEndpoints(StompEndpointRegistry registry) {
                // Permitir patterns para localhost e 127.0.0.1 em portas dinâmicas
                registry.addEndpoint("/ws")
                                .setAllowedOriginPatterns(
                                                "http://localhost:3000",
                                                "http://localhost:5173",
                                                "http://127.0.0.1:3000",
                                                "http://127.0.0.1:5173",
                                                "http://localhost:8080",
                                                "http://localhost:*",
                                                "http://127.0.0.1:*")
                                .withSockJS();

                registry.addEndpoint("/ws")
                                .setAllowedOriginPatterns(
                                                "http://localhost:3000",
                                                "http://localhost:5173",
                                                "http://127.0.0.1:3000",
                                                "http://127.0.0.1:5173",
                                                "http://localhost:8080",
                                                "http://localhost:*",
                                                "http://127.0.0.1:*");
        }

        @Override
        public void configureClientInboundChannel(ChannelRegistration registration) {
                registration.interceptors(new ChannelInterceptor() {
                        // Aqui pode-se adicionar interceptor para validar JWT em WebSocket
                        // Em produção, implementar validação JWT para conexões WebSocket
                });
        }
}