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
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.georchestra.security.model.GeorchestraUser;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.security.web.server.authentication.ServerAuthenticationConverter;
import org.springframework.util.StringUtils;
import org.springframework.web.server.ServerWebExchange;

import reactor.core.publisher.Mono;

class PreauthAuthenticationManager implements ReactiveAuthenticationManager, ServerAuthenticationConverter {

    static final String PREAUTH_HEADER_NAME = "sec-georchestra-preauthenticated";

    private static final String PREAUTH_USERNAME = "preauth-username";
    private static final String PREAUTH_EMAIL = "preauth-email";
    private static final String PREAUTH_FIRSTNAME = "preauth-firstname";
    private static final String PREAUTH_LASTNAME = "preauth-lastname";
    private static final String PREAUTH_ORG = "preauth-org";
    private static final String PREAUTH_ROLES = "preauth-roles";

    /**
     * @return {@code Mono.empty()} if the pre-auth request headers are not
     *         provided,
     */
    @Override
    public Mono<Authentication> convert(ServerWebExchange exchange) {
        if (isPreAuthenticated(exchange)) {
            Map<String, String> credentials = extract(exchange.getRequest().getHeaders());
            String username = credentials.get(PREAUTH_USERNAME);
            if (!StringUtils.hasText(username)) {
                throw new IllegalStateException("Pre-authenticated user headers not provided");
            }
            PreAuthenticatedAuthenticationToken authentication = new PreAuthenticatedAuthenticationToken(username,
                    credentials);
            return Mono.just(authentication);
        }
        return Mono.empty();
    }

    private Map<String, String> extract(HttpHeaders headers) {
        return headers.toSingleValueMap().entrySet().stream().filter(e -> e.getKey().startsWith("preauth-"))
                .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));
    }

    @Override
    public Mono<Authentication> authenticate(Authentication authentication) {
        return Mono.just(authentication);
    }

    public static boolean isPreAuthenticated(ServerWebExchange exchange) {
        HttpHeaders requestHeaders = exchange.getRequest().getHeaders();
        final String preAuthHeader = requestHeaders.getFirst(PREAUTH_HEADER_NAME);
        final boolean preAuthenticated = "true".equalsIgnoreCase(preAuthHeader);
        return preAuthenticated;
    }

    public static GeorchestraUser map(Map<String, String> requestHeaders) {
        String username = requestHeaders.get(PREAUTH_USERNAME);
        String email = requestHeaders.get(PREAUTH_EMAIL);
        String firstName = requestHeaders.get(PREAUTH_FIRSTNAME);
        String lastName = requestHeaders.get(PREAUTH_LASTNAME);
        String org = requestHeaders.get(PREAUTH_ORG);
        String rolesValue = requestHeaders.get(PREAUTH_ROLES);
        List<String> roleNames = Optional.ofNullable(rolesValue)
                .map(roles -> Stream
                        .concat(Stream.of("ROLE_USER"), Stream.of(roles.split(";")).filter(StringUtils::hasText))
                        .distinct())
                .orElse(Stream.of("ROLE_USER")).collect(Collectors.toList());

        GeorchestraUser user = new GeorchestraUser();
        user.setUsername(username);
        user.setEmail(email);
        user.setFirstName(firstName);
        user.setLastName(lastName);
        user.setOrganization(org);
        user.setRoles(roleNames);
        return user;
    }

    public void removePreauthHeaders(HttpHeaders mutableHeaders) {
        mutableHeaders.remove(PREAUTH_HEADER_NAME);
        mutableHeaders.remove(PREAUTH_USERNAME);
        mutableHeaders.remove(PREAUTH_EMAIL);
        mutableHeaders.remove(PREAUTH_FIRSTNAME);
        mutableHeaders.remove(PREAUTH_LASTNAME);
        mutableHeaders.remove(PREAUTH_ORG);
        mutableHeaders.remove(PREAUTH_ROLES);
    }
}
