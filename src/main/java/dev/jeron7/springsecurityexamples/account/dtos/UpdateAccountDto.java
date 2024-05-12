package dev.jeron7.springsecurityexamples.account.dtos;

import com.fasterxml.jackson.annotation.JsonProperty;
import dev.jeron7.springsecurityexamples.account.Role;

public record UpdateAccountDto(
        @JsonProperty("first_name")
        String firstName,
        @JsonProperty("last_name")
        String lastName,
        String email,
        String password,
        Role role) {
}
