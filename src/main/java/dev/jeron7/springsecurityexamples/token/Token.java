package dev.jeron7.springsecurityexamples.token;

import dev.jeron7.springsecurityexamples.account.Account;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.UUID;

@Entity
@Getter
@NoArgsConstructor
public class Token {
    @Id
    private UUID id;

    @Column(columnDefinition = "TEXT", nullable = false)
    private String accessToken;

    @Column(columnDefinition = "TEXT", nullable = false)
    private String refreshToken;

    @ManyToOne
    @JoinColumn(name = "account_id")
    private Account account;

    @Setter
    private boolean active;

    public Token(UUID id, String accessToken, String refreshToken, Account account) {
        this.id = id;
        this.accessToken = accessToken;
        this.refreshToken = refreshToken;
        this.account = account;
        this.active = true;
    }
}
