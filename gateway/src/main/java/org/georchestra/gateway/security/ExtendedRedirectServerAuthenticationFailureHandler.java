package org.georchestra.gateway.security;

import java.net.URI;

import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.server.DefaultServerRedirectStrategy;
import org.springframework.security.web.server.ServerRedirectStrategy;
import org.springframework.security.web.server.WebFilterExchange;
import org.springframework.security.web.server.authentication.RedirectServerAuthenticationFailureHandler;
import org.springframework.util.Assert;

import reactor.core.publisher.Mono;

public class ExtendedRedirectServerAuthenticationFailureHandler extends RedirectServerAuthenticationFailureHandler {

    private URI location;

    private static String INVALID_CREDENTIALS = "invalid_credentials";
    private static String EXPIRED_PASSWORD = "expired_password";
    private static String EXPIRED_MESSAGE = "Your password has expired";
    private ServerRedirectStrategy redirectStrategy = new DefaultServerRedirectStrategy();

    public ExtendedRedirectServerAuthenticationFailureHandler(String location) {
        super(location);
        Assert.notNull(location, "location cannot be null");
        this.location = URI.create(location);
    }

    @Override
    public Mono<Void> onAuthenticationFailure(WebFilterExchange webFilterExchange, AuthenticationException exception) {
        this.location = URI.create("login?error");
        if (exception instanceof org.springframework.security.authentication.BadCredentialsException) {
            this.location = URI.create("login?error=" + INVALID_CREDENTIALS);
        } else if (exception instanceof org.springframework.security.authentication.LockedException
                && exception.getMessage().equals(EXPIRED_MESSAGE)) {
            this.location = URI.create("login?error=" + EXPIRED_PASSWORD);
        }
        return this.redirectStrategy.sendRedirect(webFilterExchange.getExchange(), this.location);
    }

}
