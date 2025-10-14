package com.securemessaging.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Arrays;
import java.util.List;

@Configuration
public class CorsConfig {

        @Value("${cors.allowed.origins:http://localhost:3000,http://localhost:5173,http://127.0.0.1:3000,http://127.0.0.1:5173}")
        private String[] allowedOrigins;

        @Value("${cors.allowed.methods:GET,POST,PUT,DELETE,OPTIONS,PATCH,HEAD}")
        private String[] allowedMethods;

        @Value("${cors.allowed.headers:Authorization,Content-Type,Accept,Origin,User-Agent,Cache-Control,Keep-Alive,X-Requested-With,If-Modified-Since,X-File-Name}")
        private String[] allowedHeaders;

        @Value("${cors.exposed.headers:Authorization,Content-Type,Content-Disposition,X-File-Name}")
        private String[] exposedHeaders;

        @Value("${cors.allow.credentials:true}")
        private boolean allowCredentials;

        @Value("${cors.max.age:3600}")
        private long maxAge;

        @Bean
        public CorsConfigurationSource corsConfigurationSource() {
                CorsConfiguration configuration = new CorsConfiguration();

                // Converter arrays para listas
                List<String> originsList = Arrays.asList(allowedOrigins);
                List<String> methodsList = Arrays.asList(allowedMethods);
                List<String> headersList = Arrays.asList(allowedHeaders);
                List<String> exposedHeadersList = Arrays.asList(exposedHeaders);

                configuration.setAllowedOrigins(originsList);
                configuration.setAllowedMethods(methodsList);
                configuration.setAllowedHeaders(headersList);
                configuration.setExposedHeaders(exposedHeadersList);
                configuration.setAllowCredentials(allowCredentials);
                configuration.setMaxAge(maxAge);

                UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
                source.registerCorsConfiguration("/**", configuration);
                return source;
        }
}