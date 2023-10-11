/*
 * Copyright (C) 2023 by the geOrchestra PSC
 *
 * This file is part of geOrchestra.
 *
 * geOrchestra is free software: you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option)
 * any later version.
 *
 * geOrchestra is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * geOrchestra.  If not, see <http://www.gnu.org/licenses/>.
 */
package org.georchestra.gateway.security.ldap.accounts;

import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

import org.georchestra.commons.security.SecurityHeaders;
import org.georchestra.ds.DataServiceException;
import org.georchestra.ds.roles.RoleDao;
import org.georchestra.ds.security.UserMapperImpl;
import org.georchestra.ds.security.UsersApiImpl;
import org.georchestra.ds.users.Account;
import org.georchestra.ds.users.AccountDao;
import org.georchestra.ds.users.AccountFactory;
import org.georchestra.ds.users.DuplicatedEmailException;
import org.georchestra.ds.users.DuplicatedUidException;
import org.georchestra.ds.users.UserRule;
import org.georchestra.gateway.model.GeorchestraUsers;
import org.georchestra.gateway.security.GeorchestraUserMapper;
import org.georchestra.gateway.security.ldap.LdapConfigProperties;
import org.georchestra.gateway.security.preauth.ResolveHttpHeadersGeorchestraUserFilter;
import org.georchestra.security.model.GeorchestraUser;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.ldap.NameNotFoundException;
import org.springframework.web.server.ServerWebExchange;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Mono;

/**
 * A {@link GlobalFilter} that creates an LDAP user if the current
 * {@link GeorchestraUser} comes from a pre-authenticated request headers set,
 * and it doesn't exist.
 * <p>
 * Runs after {@link ResolveHttpHeadersGeorchestraUserFilter}, and expects a
 * request header {@literal sec-georchestra-preauthenticated} with value
 * {@code true} and an existing {@link GeorchestraUser}.
 * <p>
 * If the LDAP user exists, {@link GeorchestraUsers#store replaces} the current
 * user by the one from LDAP, otherwise creates it.
 * 
 * @see ResolveHttpHeadersGeorchestraUserFilter
 * @see GeorchestraUserMapper
 */
@RequiredArgsConstructor
@Slf4j(topic = "org.georchestra.gateway.security")
public class CreateNonExistingPreauthUserFilter implements GlobalFilter, Ordered {

    public static final int ORDER = ResolveHttpHeadersGeorchestraUserFilter.ORDER + 1;

    private final LdapConfigProperties config;

    private final AccountDao accountDao;

    private final RoleDao roleDao;

    /**
     * Runs after {@link ResolveHttpHeadersGeorchestraUserFilter}
     */
    public @Override int getOrder() {
        return ORDER;
    }

    public @Override Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        final boolean preAuthenticated = ResolveHttpHeadersGeorchestraUserFilter.isPreAuthenticated(exchange);
        final boolean createNonExistingUsersInLDAP = config.isCreateNonExistingUsersInLDAP();

        if (preAuthenticated && createNonExistingUsersInLDAP) {
            final GeorchestraUser preAuth = GeorchestraUsers.resolve(exchange).orElseThrow();
            GeorchestraUser ldapUser = getOrCreate(preAuth);
            GeorchestraUsers.store(exchange, ldapUser);
        }

        return chain.filter(exchange);
    }

    private GeorchestraUser getOrCreate(GeorchestraUser preAuth) {
        Optional<GeorchestraUser> existing = findByUsername(preAuth.getUsername());
        return existing.orElseGet(() -> create(preAuth));
    }

    private GeorchestraUser create(GeorchestraUser preAuth) {
        Account newAccount = mapToAccountBrief(preAuth);
        try {
            accountDao.insert(newAccount);
        } catch (DataServiceException | DuplicatedUidException | DuplicatedEmailException e) {
            throw new IllegalStateException(e);
        }

        try {// account created, add roles
            for (String role : preAuth.getRoles()) {
                roleDao.addUser(role, newAccount);
            }
        } catch (NameNotFoundException | DataServiceException e) {
            try {// roll-back account
                accountDao.delete(newAccount);
            } catch (NameNotFoundException | DataServiceException e1) {
                log.warn("Error reverting user creation after roleDao update failure", e1);
            }
            throw new IllegalStateException(e);
        }
        return findByUsername(preAuth.getUsername()).orElseThrow(
                () -> new IllegalStateException("User " + preAuth.getUsername() + " not found right after creation"));
    }

    private Account mapToAccountBrief(GeorchestraUser preAuth) {
        String username = preAuth.getUsername();
        String email = preAuth.getEmail();
        String firstName = preAuth.getFirstName();
        String lastName = preAuth.getLastName();
        String org = preAuth.getOrganization();
        String password = null;
        String phone = "";
        String title = "";
        String description = "";
        Account newAccount = AccountFactory.createBrief(username, password, firstName, lastName, email, phone, title,
                description);
        newAccount.setPending(false);
        newAccount.setOrg(org);
        return newAccount;
    }

    protected Optional<GeorchestraUser> findByUsername(String username) {
        UserMapperImpl mapper = new UserMapperImpl();
        mapper.setRoleDao(roleDao);
        List<String> protectedUsers = Collections.emptyList();
        UserRule rule = new UserRule();
        rule.setListOfprotectedUsers(protectedUsers.toArray(String[]::new));
        UsersApiImpl usersApi = new UsersApiImpl();
        usersApi.setAccountsDao(accountDao);
        usersApi.setMapper(mapper);
        usersApi.setUserRule(rule);

        Optional<GeorchestraUser> userOpt = usersApi.findByUsername(username);
        if (userOpt.isPresent()) {
            List<String> roles = userOpt.get().getRoles().stream().map(r -> r.contains("ROLE_") ? r : "ROLE_" + r)
                    .collect(Collectors.toList());
            if (roles.isEmpty()) {
                roles.add("ROLE_USER");
            }
            userOpt.get().setRoles(roles);
        }
        return userOpt;
    }

    protected GeorchestraUser map(HttpHeaders requestHeaders) {
        String username = requestHeaders.getFirst(SecurityHeaders.SEC_USERNAME);
        String email = requestHeaders.getFirst(SecurityHeaders.SEC_EMAIL);
        String firstName = requestHeaders.getFirst(SecurityHeaders.SEC_FIRSTNAME);
        String lastName = requestHeaders.getFirst(SecurityHeaders.SEC_LASTNAME);
        String org = requestHeaders.getFirst(SecurityHeaders.SEC_ORG);

        GeorchestraUser user = new GeorchestraUser();
        user.setUsername(username);
        user.setEmail(email);
        user.setFirstName(firstName);
        user.setLastName(lastName);
        user.setOrganization(org);
        user.setRoles(List.of("ROLE_USER"));
        return user;
    }

}