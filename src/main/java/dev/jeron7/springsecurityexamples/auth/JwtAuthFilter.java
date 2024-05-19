package dev.jeron7.springsecurityexamples.auth;

import dev.jeron7.springsecurityexamples.auth.Helpers.HttpServletRequestUtil;
import dev.jeron7.springsecurityexamples.token.TokenService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.antlr.v4.runtime.misc.NotNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Objects;

@Component
public class JwtAuthFilter extends OncePerRequestFilter {

    private final TokenService tokenService;

    public JwtAuthFilter(TokenService tokenService) {
        this.tokenService = Objects.requireNonNull(tokenService);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        if (ignoreRequest(request)) {
            filterChain.doFilter(request, response);
            return;
        }

        String accessToken = HttpServletRequestUtil.extractFromBearer(request);
        if (tokenService.isValidAndActiveAccessToken(accessToken)) {
            var token = tokenService.findByTokenStr(accessToken);
            var securityContext = SecurityContextHolder.getContext();

            if (token != null && securityContext.getAuthentication() == null) {
                UserDetails userDetails = token.getAccount();
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
        return isAuthServletPath || !HttpServletRequestUtil.hasBearerAuthHeader(request);
    }
}
