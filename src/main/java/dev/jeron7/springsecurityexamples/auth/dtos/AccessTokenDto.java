package dev.jeron7.springsecurityexamples.auth.dtos;

import com.fasterxml.jackson.annotation.JsonProperty;

public record AccessTokenDto(@JsonProperty("access_token") String accessToken) {
}
