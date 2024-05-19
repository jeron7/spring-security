package dev.jeron7.springsecurityexamples.account.dtos;

import com.fasterxml.jackson.annotation.JsonProperty;
import dev.jeron7.springsecurityexamples.account.Account;
import org.springframework.security.core.GrantedAuthority;

import java.util.List;
import java.util.UUID;

public record AccountDetailsDto(
        UUID id,
        @JsonProperty("full_name") String fullName,
        String email,
        List<? extends GrantedAuthority> privileges
) {
    public static AccountDetailsDto from(Account account) {
        var fullName = STR."\{account.getFirstName()} \{account.getLastName()}";
        var privileges = account.getAuthorities().stream().toList();
        return new AccountDetailsDto(account.getId(), fullName, account.getUsername(), privileges);
    }
}
