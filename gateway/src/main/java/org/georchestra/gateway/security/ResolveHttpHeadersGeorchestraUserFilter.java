/*
 * Copyright (C) 2022 by the geOrchestra PSC
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
package org.georchestra.gateway.security;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.georchestra.ds.DataServiceException;
import org.georchestra.ds.roles.Role;
import org.georchestra.ds.roles.RoleDao;
import org.georchestra.ds.security.UserMapperImpl;
import org.georchestra.ds.security.UsersApiImpl;
import org.georchestra.ds.users.*;
import org.georchestra.gateway.model.GeorchestraUsers;
import org.georchestra.gateway.security.ldap.LdapConfigProperties;
import org.georchestra.security.model.GeorchestraUser;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnExpression;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.cloud.gateway.filter.RouteToRequestUrlFilter;
import org.springframework.core.Ordered;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

@RequiredArgsConstructor
@Slf4j(topic = "org.georchestra.gateway.security")
@ConditionalOnExpression("${georchestra.gateway.headerAuthentication:false}")
public class ResolveHttpHeadersGeorchestraUserFilter implements GlobalFilter, Ordered {

    @Autowired
    LdapConfigProperties config;

    @Autowired(required = false)
    private AccountDao accountDao;

    @Autowired(required = false)
    private RoleDao roleDao;

    public static final int ORDER = RouteToRequestUrlFilter.ROUTE_TO_URL_FILTER_ORDER + 2;

    public @Override int getOrder() {
        return ORDER;
    }

    public @Override Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        if (exchange.getRequest().getHeaders().containsKey("sec-mellon-name-id")) {
            if (config.isCreateNonExistingUsersInLDAP()) {
                String username = exchange.getRequest().getHeaders().get("sec-username").get(0);
                Optional<GeorchestraUser> userOpt = map(username);

                if (userOpt.isEmpty()) {
                    try {
                        String email = exchange.getRequest().getHeaders().get("sec-email").get(0);
                        String longname = exchange.getRequest().getHeaders().get("sec-longname").get(0);
                        String org = exchange.getRequest().getHeaders().get("sec-org").get(0);
                        Account newAccount = AccountFactory.createBrief(username, null, longname.split(" ")[0],
                                longname.split(" ")[1], email, "", "", "");
                        newAccount.setPending(false);
                        newAccount.setOrg(org);
                        accountDao.insert(newAccount);
                        roleDao.addUser(Role.USER, newAccount);
                        userOpt = map(username);
                    } catch (DuplicatedUidException e) {
                        throw new IllegalStateException(e);
                    } catch (DuplicatedEmailException e) {
                        throw new IllegalStateException(e);
                    } catch (DataServiceException e) {
                        throw new IllegalStateException(e);
                    }
                }
                GeorchestraUsers.store(exchange, userOpt.orElse(null));
            } else {
                GeorchestraUsers.store(exchange, map(exchange).orElse(null));
            }
            return chain.filter(exchange);
        } else {
            return chain.filter(exchange);
        }
    }

    protected Optional<GeorchestraUser> map(String username) {
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
            userOpt.get().setOrganization("INRAE");
        }
        return userOpt;
    }

    protected Optional<GeorchestraUser> map(ServerWebExchange exchange) {
        String username = exchange.getRequest().getHeaders().get("sec-username").get(0);
        String email = exchange.getRequest().getHeaders().get("sec-email").get(0);
        String givenName = exchange.getRequest().getHeaders().get("sec-longname").get(0);
        String org = exchange.getRequest().getHeaders().get("sec-org").get(0);
        GeorchestraUser user = new GeorchestraUser();
        user.setUsername(username);
        user.setEmail(email);
        user.setFirstName(givenName);
        user.setOrganization(org);
        List<String> roles = user.getRoles().stream().map(r -> r.contains("ROLE_") ? r : "ROLE_" + r)
                .collect(Collectors.toList());
        if (roles.isEmpty()) {
            roles.add("ROLE_USER");
        }
        user.setRoles(roles);
        user.setOrganization("INRAE");
        return Optional.of(user);
    }

}