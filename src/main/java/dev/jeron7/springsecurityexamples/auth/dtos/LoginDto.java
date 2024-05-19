package dev.jeron7.springsecurityexamples.auth.dtos;

import com.fasterxml.jackson.annotation.JsonProperty;

public record LoginDto(
        @JsonProperty("access_token") String accessToken,
        @JsonProperty("refresh_token") String refreshToken,
        @JsonProperty("minutes_to_expire") long minutesToExpire
) {
}
