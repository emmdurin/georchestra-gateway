package org.georchestra.gateway.security.preauth;

import java.util.List;

import org.georchestra.commons.security.SecurityHeaders;
import org.georchestra.security.model.GeorchestraUser;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.security.web.server.authentication.ServerAuthenticationConverter;
import org.springframework.util.StringUtils;
import org.springframework.web.server.ServerWebExchange;

import reactor.core.publisher.Mono;

public class PreauthAuthenticationManager implements ReactiveAuthenticationManager, ServerAuthenticationConverter {

    static final String PREAUTH_HEADER_NAME = "sec-georchestra-preauthenticated";

    /**
     * @return {@code Mono.empty()} if the pre-auth request headers are not
     *         provided,
     */
    @Override
    public Mono<Authentication> convert(ServerWebExchange exchange) {
        if (isPreAuthenticated(exchange)) {
            GeorchestraUser preauth = map(exchange.getRequest().getHeaders());
            if (!StringUtils.hasText(preauth.getUsername())) {
                throw new IllegalStateException("Pre-authenticated user headers not provided");
            }
            PreAuthenticatedAuthenticationToken authentication = new PreAuthenticatedAuthenticationToken(
                    preauth.getUsername(), preauth);
            return Mono.just(authentication);
        }
        return Mono.empty();
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
