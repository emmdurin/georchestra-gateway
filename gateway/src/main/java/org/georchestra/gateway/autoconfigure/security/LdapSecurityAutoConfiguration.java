/*
 * Copyright (C) 2022 by the geOrchestra PSC
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
package org.georchestra.gateway.autoconfigure.security;

import javax.annotation.PostConstruct;

import org.georchestra.gateway.security.ldap.LdapAuthenticationConfiguration;
import org.georchestra.gateway.security.ldap.basic.BasicLdapAuthenticationConfiguration;
import org.georchestra.gateway.security.ldap.extended.ExtendedLdapAuthenticationConfiguration;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.context.annotation.Import;

import lombok.extern.slf4j.Slf4j;

/**
 * {@link EnableAutoConfiguration AutoConfiguration} to set up LDAP security
 * 
 * @see LdapAuthenticationConfiguration
 * @see BasicLdapAuthenticationConfiguration
 * @see ExtendedLdapAuthenticationConfiguration
 * @see ActiveDirectoryAuthenticationConfiguration
 */
@AutoConfiguration
@ConditionalOnLdapEnabled
@Import(LdapAuthenticationConfiguration.class)
@Slf4j(topic = "org.georchestra.gateway.autoconfigure.security")
public class LdapSecurityAutoConfiguration {

    public @PostConstruct void log() {
        log.info("georchestra LDAP security enabled");
    }
}
