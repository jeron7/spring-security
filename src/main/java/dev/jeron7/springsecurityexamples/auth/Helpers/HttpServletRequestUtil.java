package dev.jeron7.springsecurityexamples.auth.Helpers;

import jakarta.servlet.http.HttpServletRequest;

public class HttpServletRequestUtil {

    public static String extractFromBearer(HttpServletRequest request) {
        String authHeader = request.getHeader("Authorization");
        return authHeader.substring(7);
    }

    public static boolean hasBearerAuthHeader(HttpServletRequest request) {
        var authHeader = request.getHeader("Authorization");
        return authHeader != null && authHeader.startsWith("Bearer");
    }
}
