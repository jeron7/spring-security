package dev.jeron7.springsecurityexamples.token;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.UUID;

@Entity
@Getter
@NoArgsConstructor
public class Token {
    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    public UUID id;

    @Column(columnDefinition = "TEXT", nullable = false)
    public String accessToken;

    @Column(columnDefinition = "TEXT", nullable = false)
    public String refreshToken;

    @Setter
    public boolean active;

    public Token(String accessToken, String refreshToken) {
        this.active = true;
        this.accessToken = accessToken;
        this.refreshToken = refreshToken;
    }
}
