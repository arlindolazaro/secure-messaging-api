package com.securemessaging.security;

import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;

@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtTokenProvider jwtTokenProvider;
    private final UserDetailsService userDetailsService;

    public JwtAuthenticationFilter(JwtTokenProvider jwtTokenProvider, UserDetailsService userDetailsService) {
        this.jwtTokenProvider = jwtTokenProvider;
        this.userDetailsService = userDetailsService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        try {
            String token = getJwtFromRequest(request);

            if (token != null && jwtTokenProvider.validateToken(token)) {
                String username = jwtTokenProvider.getUsernameFromToken(token);

                if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
                    UserDetails userDetails = userDetailsService.loadUserByUsername(username);

                    // ✅ CORREÇÃO: Validar token com UserDetails também
                    if (jwtTokenProvider.validateToken(token, userDetails)) {
                        UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                                userDetails,
                                null,
                                userDetails.getAuthorities());

                        // ✅ ADICIONADO: Detalhes da requisição
                        authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                        SecurityContext context = SecurityContextHolder.createEmptyContext();
                        context.setAuthentication(authentication);
                        SecurityContextHolder.setContext(context);

                        logger.debug("Usuário autenticado: " + username + " | URI: " + request.getRequestURI());
                    }
                }
            }
        } catch (Exception e) {
            logger.error("Não foi possível definir a autenticação do usuário no contexto de segurança", e);
            // Não interromper a cadeia de filtros - deixar passar para o próximo filtro
        }

        filterChain.doFilter(request, response);
    }

    private String getJwtFromRequest(HttpServletRequest request) {
        // Tentar obter do header Authorization
        String bearerToken = request.getHeader("Authorization");
        if (bearerToken != null && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7);
        }

        // ✅ ADICIONADO: Tentar obter do parâmetro de query (para WebSocket)
        String tokenParam = request.getParameter("token");
        if (tokenParam != null && !tokenParam.trim().isEmpty()) {
            return tokenParam;
        }

        return null;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = request.getServletPath();
        String method = request.getMethod();

        // ✅ CORREÇÃO: Lista mais abrangente de endpoints públicos
        return path.startsWith("/api/auth/") ||
                path.startsWith("/swagger-ui/") ||
                path.startsWith("/v3/api-docs") ||
                path.startsWith("/api-docs") ||
                path.startsWith("/webjars/") ||
                path.startsWith("/swagger-resources") ||
                path.startsWith("/configuration/") ||
                path.startsWith("/ws/") ||
                path.startsWith("/websocket/") ||
                path.equals("/swagger-ui.html") ||
                path.equals("/favicon.ico") ||
                path.equals("/error") ||
                (path.equals("/api/crypto/dh/simulate") && "GET".equalsIgnoreCase(method)) ||
                (path.equals("/api/crypto/hash") && "POST".equalsIgnoreCase(method)) ||
                (path.equals("/api/crypto/generate/rsa") && "POST".equalsIgnoreCase(method)) ||
                (path.equals("/api/crypto/health") && "GET".equalsIgnoreCase(method)) ||
                (path.startsWith("/h2-console/"));
    }
}