package dev.jeron7.springsecurityexamples.account.dtos;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.Objects;

public record CreateAccountDto(@JsonProperty("first_name") String firstName,
                               @JsonProperty("last_name") String lastName,
                               String email,
                               String password) {
    public CreateAccountDto {
        Objects.requireNonNull(firstName, "First name is null.");
        if (firstName.isBlank())
            throw new IllegalArgumentException("First name is empty.");

        Objects.requireNonNull(lastName, "Last name is null.");
        if (lastName.isBlank())
            throw new IllegalArgumentException("Last name is empty.");

        Objects.requireNonNull(email, "Email is null.");
        if (email.isBlank())
            throw new IllegalArgumentException("Email is empty.");

        Objects.requireNonNull(password, "Password is null.");
        if (password.isBlank())
            throw new IllegalArgumentException("Password is empty.");
    }
}
