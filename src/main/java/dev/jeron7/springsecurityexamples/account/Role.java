package dev.jeron7.springsecurityexamples.account;

import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.Set;
import java.util.stream.Collectors;

import static dev.jeron7.springsecurityexamples.account.Privileges.*;

public enum Role {
    USER(Set.of()),
    MANAGER(Set.of(MANAGER_READ, MANAGER_WRITE)),
    ADMIN(Set.of(ADMIN_READ, ADMIN_WRITE));

    private final Set<Privileges> privileges;

    Role(Set<Privileges> privileges) {
        this.privileges = privileges;
    }

    public Set<SimpleGrantedAuthority> getPrivileges() {
        var authorities = this.privileges.stream()
                .map(privilege -> new SimpleGrantedAuthority(privilege.toString()))
                .collect(Collectors.toSet());
        authorities.add(new SimpleGrantedAuthority(STR."ROLE_\{this.name()}"));
        return authorities;
    }
}
