package dev.jeron7.springsecurityexamples.account;

import dev.jeron7.springsecurityexamples.account.dtos.AccountDetailsDto;
import dev.jeron7.springsecurityexamples.account.dtos.UpdateAccountDto;
import dev.jeron7.springsecurityexamples.account.dtos.UpdateRoleDto;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Slice;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.Objects;
import java.util.UUID;

@RestController
@RequestMapping("account")
public class AccountController {

    private final AccountService accountService;

    public AccountController(AccountService accountService) {
        this.accountService = Objects.requireNonNull(accountService);
    }

    @GetMapping("{id}")
    @PostAuthorize("hasAuthority('manager::read') or (returnObject != null ? returnObject.getBody().email() == principal.username : false)")
    public ResponseEntity<AccountDetailsDto> getById(@PathVariable UUID id) {
        var foundUser = accountService.findById(id);
        if (foundUser == null)
            return ResponseEntity.notFound().build();

        return ResponseEntity.ok(AccountDetailsDto.from(foundUser));
    }

    @PatchMapping("{id}/role")
    @PreAuthorize("hasAuthority('admin::write')")
    public ResponseEntity<AccountDetailsDto> updateRole(@PathVariable UUID id,
                                                        @RequestBody UpdateRoleDto updateRoleDto) {
        var foundUser = accountService.findById(id);
        if (foundUser == null)
            return ResponseEntity.notFound().build();

        var updatedUser = accountService.update(foundUser, new UpdateAccountDto(null,
                null,
                null,
                null,
                updateRoleDto.role()));

        return ResponseEntity.ok(AccountDetailsDto.from(updatedUser));
    }

    @GetMapping
    @PreAuthorize("hasAuthority('admin::read')")
    public ResponseEntity<Slice<AccountDetailsDto>> getAll(Pageable pageable) {
        var accounts = accountService.findAll(pageable);

        HttpHeaders headers = new HttpHeaders();
        headers.add("X-Page-Number", String.valueOf(accounts.getNumber()));
        headers.add("X-Page-Size", String.valueOf(accounts.getSize()));
        return ResponseEntity.ok()
                .headers(headers)
                .body(accounts);
    }

}
