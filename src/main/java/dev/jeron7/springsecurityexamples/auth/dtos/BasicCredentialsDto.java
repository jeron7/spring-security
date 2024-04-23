package dev.jeron7.springsecurityexamples.auth.dtos;

import java.util.Objects;

public record BasicCredentialsDto(String email, String password) {
    public BasicCredentialsDto {
        Objects.requireNonNull(email, "Email is null.");
        if (email.isBlank())
            throw new IllegalArgumentException("Email is empty.");

        Objects.requireNonNull(password, "Password is null.");
        if (password.isBlank())
            throw new IllegalArgumentException("Password is empty.");
    }
}
