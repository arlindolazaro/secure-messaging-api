package com.securemessaging.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.core.Ordered;
import org.springframework.web.filter.CorsFilter;

import java.util.Arrays;
import java.util.List;

@Configuration
public class CorsConfig {

        // Valores padrão incluem portas específicas, mas durante desenvolvimento muitas
        // vezes
        // usamos portas diferentes. Portanto aceitamos patterns que cubram localhost em
        // qualquer porta e 127.0.0.1 também.
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
                List<String> originsList = new java.util.ArrayList<>(Arrays.asList(allowedOrigins));
                List<String> methodsList = new java.util.ArrayList<>(Arrays.asList(allowedMethods));
                List<String> headersList = new java.util.ArrayList<>(Arrays.asList(allowedHeaders));
                List<String> exposedHeadersList = new java.util.ArrayList<>(Arrays.asList(exposedHeaders));

                // Usar padrões de origem permite corresponder localhost:porta e outras
                // variações. Adicionamos padrões genéricos para localhost e 127.0.0.1
                // para cobrir portas dinâmicas em desenvolvimento.
                List<String> originPatterns = new java.util.ArrayList<>(originsList);
                originPatterns.add("http://localhost:*");
                originPatterns.add("http://127.0.0.1:*");
                originPatterns.add("http://[::1]:*");
                configuration.setAllowedOriginPatterns(originPatterns);
                configuration.setAllowedMethods(methodsList);
                configuration.setAllowedHeaders(headersList);
                configuration.setExposedHeaders(exposedHeadersList);
                configuration.setAllowCredentials(allowCredentials);
                configuration.setMaxAge(maxAge);

                UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
                source.registerCorsConfiguration("/**", configuration);
                return source;
        }

        // Registrar um CorsFilter com alta precedência para garantir que endpoints
        // servidos fora do DispatcherServlet (ex: SockJS /ws/info) recebam os
        // cabeçalhos CORS antes de qualquer outro filtro.
        @Bean
        public FilterRegistrationBean<CorsFilter> corsFilterRegistrationBean() {
                UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
                source.registerCorsConfiguration("/**", buildCorsConfiguration());
                CorsFilter corsFilter = new CorsFilter(source);

                FilterRegistrationBean<CorsFilter> bean = new FilterRegistrationBean<>(corsFilter);
                bean.setOrder(Ordered.HIGHEST_PRECEDENCE);
                return bean;
        }

        // Extrai a configuração para reutilização
        private CorsConfiguration buildCorsConfiguration() {
                CorsConfiguration configuration = new CorsConfiguration();
                List<String> originsList = new java.util.ArrayList<>(Arrays.asList(allowedOrigins));
                List<String> methodsList = new java.util.ArrayList<>(Arrays.asList(allowedMethods));
                List<String> headersList = new java.util.ArrayList<>(Arrays.asList(allowedHeaders));
                List<String> exposedHeadersList = new java.util.ArrayList<>(Arrays.asList(exposedHeaders));

                // Reutilizar a mesma estratégia de patterns dinâmicos
                List<String> originPatterns = new java.util.ArrayList<>(originsList);
                originPatterns.add("http://localhost:*");
                originPatterns.add("http://127.0.0.1:*");
                originPatterns.add("http://[::1]:*");
                configuration.setAllowedOriginPatterns(originPatterns);
                configuration.setAllowedMethods(methodsList);
                configuration.setAllowedHeaders(headersList);
                configuration.setExposedHeaders(exposedHeadersList);
                configuration.setAllowCredentials(allowCredentials);
                configuration.setMaxAge(maxAge);
                return configuration;
        }
}