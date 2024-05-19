package dev.jeron7.springsecurityexamples.auth;

import dev.jeron7.springsecurityexamples.auth.Helpers.HttpServletRequestUtil;
import dev.jeron7.springsecurityexamples.token.TokenService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.stereotype.Component;

import java.util.Objects;

@Component
public class JwtLogoutHandler implements LogoutHandler {

    private final TokenService tokenService;

    public JwtLogoutHandler(TokenService tokenService) {
        this.tokenService = Objects.requireNonNull(tokenService);
    }

    @Override
    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        if (!HttpServletRequestUtil.hasBearerAuthHeader(request))
            return;

        String accessToken = HttpServletRequestUtil.extractFromBearer(request);
        if(!tokenService.isValidAndActiveAccessToken(accessToken))
            return;

        var token = tokenService.findByTokenStr(accessToken);
        tokenService.disableToken(token);

        SecurityContextHolder.clearContext();
    }
}
