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
package org.georchestra.gateway.security.preauth;

import java.util.List;

import org.georchestra.commons.security.SecurityHeaders;
import org.georchestra.gateway.model.GatewayConfigProperties;
import org.georchestra.gateway.model.GeorchestraUsers;
import org.georchestra.gateway.security.GeorchestraUserMapper;
import org.georchestra.gateway.security.ResolveGeorchestraUserGlobalFilter;
import org.georchestra.security.model.GeorchestraUser;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.util.StringUtils;
import org.springframework.web.server.ServerWebExchange;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Mono;

/**
 * A {@link GlobalFilter} that resolves the {@link GeorchestraUser} from the
 * request headers for pre-authenticated scenarios, where a proxy in front of
 * the gateway is trusted.
 * <p>
 * Runs after {@link ResolveGeorchestraUserGlobalFilter}, and expects a request
 * header {@literal sec-georchestra-preauthenticated} with value {@code true},
 * to resolve the {@link GeorchestraUser} from the following request headers:
 * <ul>
 * <li>{@literal sec-username}
 * <li>{@literal sec-firstname}
 * <li>{@literal sec-lastname}
 * <li>{@literal sec-org}
 * <li>{@literal sec-email}
 * </ul>
 * NOTE {@literal sec-roles} is NOT expected, and the pre-authenticated user
 * will only have the {@literal ROLE_USER} role.
 * <p>
 * The resolved per-request {@link GeorchestraUser user} object can then, for
 * example, be used to append the necessary {@literal sec-*} headers that relate
 * to user information to proxied http requests.
 * 
 * @see ResolveGeorchestraUserGlobalFilter
 * @see GeorchestraUserMapper
 */
@RequiredArgsConstructor
@Slf4j(topic = "org.georchestra.gateway.security.preauth")
public class ResolveHttpHeadersGeorchestraUserFilter implements GlobalFilter, Ordered {

    static final String PREAUTH_HEADER_NAME = "sec-georchestra-preauthenticated";
    public static final int ORDER = ResolveGeorchestraUserGlobalFilter.ORDER + 1;

    /**
     * Runs after {@link ResolveGeorchestraUserGlobalFilter}
     */
    public @Override int getOrder() {
        return ORDER;
    }

    public static boolean isPreAuthenticated(ServerWebExchange exchange) {
        HttpHeaders requestHeaders = exchange.getRequest().getHeaders();
        final String preAuthHeader = requestHeaders.getFirst(PREAUTH_HEADER_NAME);
        final boolean preAuthenticated = "true".equalsIgnoreCase(preAuthHeader);
        return preAuthenticated;
    }

    public @Override Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        final boolean preAuthenticated = isPreAuthenticated(exchange);
        if (preAuthenticated) {
            HttpHeaders requestHeaders = exchange.getRequest().getHeaders();
            GeorchestraUser user = map(requestHeaders);
            if (!StringUtils.hasText(user.getUsername())) {
                throw new IllegalStateException("Pre-authenticated user headers not provided");
            }
            log.debug("Got pre-authenticated user {}", user.getUsername());
            GeorchestraUsers.store(exchange, user);
        }
        return chain.filter(exchange);
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