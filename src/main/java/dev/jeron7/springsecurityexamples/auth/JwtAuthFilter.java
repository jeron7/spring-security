package dev.jeron7.springsecurityexamples.auth;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
public class JwtAuthFilter extends OncePerRequestFilter {

    private final AuthStrategy authStrategy;

    private final UserDetailsService userDetailsService;

    public JwtAuthFilter(@Qualifier("jwtAuthStrategy") AuthStrategy authStrategy,
                         UserDetailsService userDetailsService) {
        this.authStrategy = authStrategy;
        this.userDetailsService = userDetailsService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        if (ignoreRequest(request)) {
            filterChain.doFilter(request, response);
            return;
        }

        String authHeader = request.getHeader("Authorization");
        var token = authHeader.substring(7);
        var accountEmail = authStrategy.getEmail(token);
        var securityContext = SecurityContextHolder.getContext();

        if (accountEmail != null && securityContext.getAuthentication() == null) {
            UserDetails userDetails = userDetailsService.loadUserByUsername(accountEmail);

            if (authStrategy.verify(token)) {
                var authToken = UsernamePasswordAuthenticationToken.authenticated(userDetails,
                        null,
                        userDetails.getAuthorities());
                authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                securityContext.setAuthentication(authToken);
            }
        }
        filterChain.doFilter(request, response);
    }

    private boolean ignoreRequest(HttpServletRequest request) {
        var isAuthServletPath = request.getServletPath().startsWith("/auth");
        return isAuthServletPath || !isValidAuthHeader(request);
    }

    public static boolean isValidAuthHeader(HttpServletRequest request) {
        var authHeader = request.getHeader("Authorization");
        return authHeader != null && authHeader.startsWith("Bearer");
    }
}
