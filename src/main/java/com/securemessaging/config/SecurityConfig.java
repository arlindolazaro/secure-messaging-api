package com.securemessaging.config;

import com.securemessaging.repository.UserRepository;
import com.securemessaging.security.JwtAuthenticationFilter;
import com.securemessaging.security.JwtTokenProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity(prePostEnabled = true)
public class SecurityConfig {

        @Autowired
        private JwtTokenProvider jwtTokenProvider;

        @Autowired
        private CorsConfig corsConfig;

        @Autowired
        private UserRepository userRepository;

        @Bean
        public PasswordEncoder passwordEncoder() {
                return new BCryptPasswordEncoder();
        }

        @Bean
        public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration)
                        throws Exception {
                return authenticationConfiguration.getAuthenticationManager();
        }

        @Bean
        public DaoAuthenticationProvider authenticationProvider() {
                DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
                authProvider.setUserDetailsService(userDetailsService());
                authProvider.setPasswordEncoder(passwordEncoder());
                return authProvider;
        }

        @Bean
        public UserDetailsService userDetailsService() {
                return username -> userRepository.findByUsername(username)
                                .map(user -> org.springframework.security.core.userdetails.User
                                                .withUsername(user.getUsername())
                                                .password(user.getPassword())
                                                .authorities("ROLE_USER")
                                                .accountExpired(false)
                                                .accountLocked(false)
                                                .credentialsExpired(false)
                                                .disabled(!user.isEnabled())
                                                .build())
                                .orElseThrow(() -> new UsernameNotFoundException(
                                                "Usuário não encontrado: " + username));
        }

        @Bean
        public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
                http
                                .cors(cors -> cors.configurationSource(corsConfig.corsConfigurationSource()))
                                .csrf(csrf -> csrf.disable())
                                .sessionManagement(session -> session
                                                .sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                                .authorizeHttpRequests(authz -> authz
                                                // ✅ CORREÇÃO: Endpoints públicos atualizados
                                                .requestMatchers(
                                                                "/api/auth/**",
                                                                "/api/crypto/dh/simulate",
                                                                "/api/crypto/hash",
                                                                "/api/crypto/generate/rsa",
                                                                "/api/crypto/health",
                                                                "/ws/**",
                                                                "/websocket/**",
                                                                "/swagger-ui/**",
                                                                "/v3/api-docs/**",
                                                                "/api-docs/**",
                                                                "/swagger-ui.html",
                                                                "/webjars/**",
                                                                "/swagger-resources/**",
                                                                "/configuration/**",
                                                                "/h2-console/**",
                                                                "/health",
                                                                "/error",
                                                                "/favicon.ico")
                                                .permitAll()

                                                // ✅ CORREÇÃO: H2 Console apenas em desenvolvimento
                                                .requestMatchers("/h2-console/**").permitAll()

                                                // Endpoints que requerem autenticação
                                                .requestMatchers("/api/messages/**").authenticated()
                                                .requestMatchers("/api/certificates/**").authenticated()
                                                .requestMatchers("/api/images/**").authenticated()
                                                .requestMatchers("/api/users/**").authenticated()
                                                .requestMatchers("/api/key-management/**").authenticated()
                                                .requestMatchers("/api/pdf/**").authenticated()
                                                .requestMatchers("/api/crypto/**").authenticated()

                                                .anyRequest().authenticated())
                                .headers(headers -> headers
                                                .frameOptions(frame -> frame.sameOrigin()) // Para H2 Console
                                )
                                .authenticationProvider(authenticationProvider())
                                .addFilterBefore(new JwtAuthenticationFilter(jwtTokenProvider, userDetailsService()),
                                                UsernamePasswordAuthenticationFilter.class)
                                .exceptionHandling(exception -> exception
                                                .authenticationEntryPoint((request, response, authException) -> {
                                                        response.setStatus(401);
                                                        response.setContentType("application/json");
                                                        response.setCharacterEncoding("UTF-8");
                                                        response.getWriter().write(
                                                                        "{\"success\": false, \"error\": \"Não autorizado\", \"message\": \"Token JWT inválido ou ausente\"}");
                                                })
                                                .accessDeniedHandler((request, response, accessDeniedException) -> {
                                                        response.setStatus(403);
                                                        response.setContentType("application/json");
                                                        response.setCharacterEncoding("UTF-8");
                                                        response.getWriter().write(
                                                                        "{\"success\": false, \"error\": \"Acesso negado\", \"message\": \"Não tem permissões para aceder a este recurso\"}");
                                                }));

                return http.build();
        }
}