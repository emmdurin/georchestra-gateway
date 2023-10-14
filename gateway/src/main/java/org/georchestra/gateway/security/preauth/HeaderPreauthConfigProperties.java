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
package org.georchestra.gateway.security.preauth;

import java.util.List;

import org.springframework.boot.context.properties.ConfigurationProperties;

import lombok.Data;
import lombok.Generated;

/**
 * Model object representing the externalized configuration properties used to
 * set up request headers based pre-authentication.
 */
@Data
@Generated
@ConfigurationProperties(HeaderPreauthConfigProperties.PROPERTY_BASE)
public class HeaderPreauthConfigProperties {

    static final String PROPERTY_BASE = "georchestra.gateway.security.header-authentication";

    public static final String ENABLED_PROPERTY = PROPERTY_BASE + ".enabled";

    /**
     * If enabled, pre-authentication is enabled and can be performed by passing
     * true to the sec-georchestra-preauthenticated request header, and user details
     * through the following request headers: preuath-username, preuath-firstname,
     * preuath-lastname, preuath-org, preuath-email, preuath-roles
     */
    private boolean enabled = false;

    private List<String> trustedProxies;

}
