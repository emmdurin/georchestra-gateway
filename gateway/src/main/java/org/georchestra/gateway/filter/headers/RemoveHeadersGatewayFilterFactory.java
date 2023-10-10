/*
 * Copyright (C) 2021 by the geOrchestra PSC
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
package org.georchestra.gateway.filter.headers;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import org.georchestra.gateway.filter.headers.RemoveHeadersGatewayFilterFactory.RegExConfig;
import org.georchestra.gateway.model.GatewayConfigProperties;
import org.georchestra.gateway.security.ldap.LdapConfigProperties;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.cloud.gateway.filter.factory.GatewayFilterFactory;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpHeaders;
import org.springframework.http.server.reactive.ServerHttpRequest;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;
import org.springframework.util.CollectionUtils;

/**
 * {@link GatewayFilterFactory} to remove incoming HTTP request headers whose
 * names match a Java regular expression.
 * <p>
 * Use a {@code RemoveHeaders=<regular expression>} filter in a
 * {@code spring.cloud.gateway.routes.filters} route config to remove all
 * incoming request headers matching the regex.
 * <p>
 * Sample usage:
 * 
 * <pre>
 * <code>
 * spring:
 *   cloud:
 *    gateway:
 *      routes:
 *      - id: root
 *        uri: http://backend-service/context
 *        filters:
 *        - RemoveHeaders=(?i)(sec-.*|Authorization) 
 * </code>
 * </pre>
 * 
 */
@Slf4j(topic = "org.georchestra.gateway.filter.headers")
@EnableConfigurationProperties(LdapConfigProperties.class)
public class RemoveHeadersGatewayFilterFactory extends AbstractGatewayFilterFactory<RegExConfig> {

    @Autowired
    private Environment environment;

    @Value("${georchestra.gateway.security.createNonExistingUsersInLDAP:}")
    private String trusted;

    GatewayConfigProperties configProps;

    public RemoveHeadersGatewayFilterFactory(GatewayConfigProperties configProps) {
        super(RegExConfig.class);
        this.configProps = configProps;
    }

    @Override
    public List<String> shortcutFieldOrder() {
        return Arrays.asList("regEx");
    }

    @Override
    public GatewayFilter apply(RegExConfig regexConfig) {

        return (exchange, chain) -> {
            final RegExConfig config = regexConfig;// == null ? DEFAULT_SECURITY_HEADERS_CONFIG : regexConfig;
            HttpHeaders incoming = exchange.getRequest().getHeaders();

            if (config.anyMatches(incoming) && (!configProps.isHeaderAuthentication()
                    || !headersAreTrusted(exchange.getRequest().getRemoteAddress().getAddress().toString()))) {
                ServerHttpRequest request = exchange.getRequest().mutate().headers(config::removeMatching).build();
                exchange = exchange.mutate().request(request).build();
            }

            return chain.filter(exchange);
        };
    }

    private boolean headersAreTrusted(String serverAddress) {
        // If trustedProxies list is empty, we consider the proxy chain is trusted
        if (configProps != null && CollectionUtils.isEmpty(configProps.getHeaderTrustedProxies())) {
            return true;
        }
        if (configProps != null && !configProps.getHeaderTrustedProxies().isEmpty()
                && configProps.isHeaderAuthentication()) {
            if (configProps.getHeaderTrustedProxies().stream().filter(e -> serverAddress.contains(e))
                    .collect(Collectors.toList()).size() > 0) {
                return true;
            }
            if (configProps.getHeaderTrustedProxies().stream().filter(e -> {
                try {
                    return InetAddress.getByName(serverAddress).toString().contains(e);
                } catch (UnknownHostException exp) {
                    return false;
                }
            }).collect(Collectors.toList()).size() > 0) {
                return true;
            }
        }
        return false;
    }

    @NoArgsConstructor
    public static class RegExConfig {

        private @Getter String regEx;

        private transient Pattern compiled;

        public RegExConfig(String regEx) {
            setRegEx(regEx);
        }

        public void setRegEx(String regEx) {
            Objects.requireNonNull(regEx, "regular expression can't be null");
            this.regEx = regEx;
            this.compiled = Pattern.compile(regEx);
        }

        private Pattern pattern() {
            Objects.requireNonNull(compiled, "regular expression can't be null");
            return compiled;
        }

        boolean matches(@NonNull String headerName) {
            return pattern().matcher(headerName).matches();
        }

        boolean anyMatches(@NonNull HttpHeaders headers) {
            return headers.keySet().stream().anyMatch(this::matches);
        }

        void removeMatching(@NonNull HttpHeaders headers) {
            new HashSet<>(headers.keySet()).stream()//
                    .filter(this::matches)//
                    .peek(name -> log.trace("Removing header {}", name))//
                    .forEach(headers::remove);
        }
    }

}
