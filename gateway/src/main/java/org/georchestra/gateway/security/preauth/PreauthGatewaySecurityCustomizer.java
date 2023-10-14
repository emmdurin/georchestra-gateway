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

import org.georchestra.gateway.security.ServerHttpSecurityCustomizer;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.authentication.AuthenticationWebFilter;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;

import lombok.RequiredArgsConstructor;
import reactor.core.publisher.Mono;

public class PreauthGatewaySecurityCustomizer implements ServerHttpSecurityCustomizer {

    @SuppressWarnings("deprecation")
    @Override
    public void customize(ServerHttpSecurity http) {
        PreauthAuthenticationManager authenticationManager = new PreauthAuthenticationManager();
        AuthenticationWebFilter headerFilter = new AuthenticationWebFilter(authenticationManager);

        // return Mono.empty() if preauth headers not provided
        headerFilter.setAuthenticationConverter(authenticationManager::convert);
        http.addFilterAt(headerFilter, SecurityWebFiltersOrder.FIRST);
        http.addFilterAt(new RemovePreauthHeadersWebFilter(authenticationManager), SecurityWebFiltersOrder.LAST);
    }

    @RequiredArgsConstructor
    static class RemovePreauthHeadersWebFilter implements WebFilter {

        private final PreauthAuthenticationManager manager;

        @Override
        public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
            ServerHttpRequest request = exchange.getRequest().mutate().headers(manager::removePreauthHeaders).build();
            exchange = exchange.mutate().request(request).build();
            return chain.filter(exchange);
        }
    }
}
