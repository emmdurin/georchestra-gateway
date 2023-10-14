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

import org.georchestra.gateway.security.GeorchestraUserMapper;
import org.georchestra.security.model.GeorchestraUser;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;

/**
 * {@link Configuration @Configuration} to enable request headers
 * pre-authentication.
 * <p>
 * <ul>
 * <li>{@link PreauthGatewaySecurityCustomizer} performs authentication based on
 * incoming {@literal sec-*} headers and produces a
 * {@link PreAuthenticatedAuthenticationToken}, provided the
 * {@code sec-georchestra-preauthenticated} header has a value of {@code true}.
 * This is intended to be sent by a reverse proxy, prior sanitization of
 * {@code sec-*} headers from client requests to avoid fraudulent requests.
 * <p>
 * The following request headers are parsed:
 * <ul>
 * <li>{@literal sec-username}
 * <li>{@literal sec-firstname}
 * <li>{@literal sec-lastname}
 * <li>{@literal sec-org}
 * <li>{@literal sec-email}
 * <li>{@literal sec-roles}
 * </ul>
 * NOTE {@literal sec-roles} is NOT mandatory, and the pre-authenticated user
 * will only have the {@literal ROLE_USER} role when {@code sec-roles} is not
 * provided.
 * <li>{@link PreauthenticatedUserMapperExtension} maps the
 * {@link PreAuthenticatedAuthenticationToken} to a {@link GeorchestraUser} when
 * {@link GeorchestraUserMapper#resolve(org.springframework.security.core.Authentication)
 * GeorchestraUserMapper.resolve(Authentication)} requests it.
 * </ul>
 * 
 */
@Configuration
public class HeaderPreAuthenticationConfiguration {

    @Bean
    PreauthGatewaySecurityCustomizer preauthGatewaySecurityCustomizer() {
        return new PreauthGatewaySecurityCustomizer();
    }

    @Bean
    PreauthenticatedUserMapperExtension preauthenticatedUserMapperExtension() {
        return new PreauthenticatedUserMapperExtension();
    }

    /**
     * Filter to enable pre-authentication from a trusted proxy
     */
//    @Bean
//    ResolveHttpHeadersGeorchestraUserFilter resolveHttpHeadersGeorchestraUserFilter() {
//        return new ResolveHttpHeadersGeorchestraUserFilter();
//    }

}
