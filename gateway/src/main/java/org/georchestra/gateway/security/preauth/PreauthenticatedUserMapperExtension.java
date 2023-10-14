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

import java.util.Map;
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
                .filter(Map.class::isInstance)//
                .map(Map.class::cast).map(PreauthAuthenticationManager::map);
    }

}
