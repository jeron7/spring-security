package dev.jeron7.springsecurityexamples.token;

import dev.jeron7.springsecurityexamples.account.Account;
import org.springframework.data.repository.CrudRepository;

import java.util.List;
import java.util.UUID;

public interface TokenRepository extends CrudRepository<Token, UUID> {
    List<Token> findByAccountAndActiveTrue(Account account);
}
