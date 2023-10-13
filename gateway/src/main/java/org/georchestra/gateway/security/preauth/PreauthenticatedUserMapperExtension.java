package org.georchestra.gateway.security.preauth;

import java.util.Optional;

import org.georchestra.gateway.security.GeorchestraUserMapperExtension;
import org.georchestra.security.model.GeorchestraUser;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;

public class PreauthenticatedUserMapperExtension implements GeorchestraUserMapperExtension {

    @Override
    public Optional<GeorchestraUser> resolve(Authentication authToken) {
        return Optional.ofNullable(authToken)//
                .filter(PreAuthenticatedAuthenticationToken.class::isInstance)
                .map(PreAuthenticatedAuthenticationToken.class::cast)//
                .map(PreAuthenticatedAuthenticationToken::getCredentials)//
                .filter(GeorchestraUser.class::isInstance)//
                .map(GeorchestraUser.class::cast);
    }

}
