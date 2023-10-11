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
package org.georchestra.gateway.autoconfigure.security;

import javax.annotation.PostConstruct;

import org.georchestra.gateway.security.oauth2.OAuth2Configuration;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;

import lombok.extern.slf4j.Slf4j;

@AutoConfiguration
@Slf4j(topic = "org.georchestra.gateway.autoconfigure.security")
@Import({ OAuth2SecurityAutoConfiguration.Enabled.class, OAuth2SecurityAutoConfiguration.Disabled.class })
public class OAuth2SecurityAutoConfiguration {
    private static final String ENABLED_PROP = "georchestra.gateway.security.oauth2.enabled";

    @Import(OAuth2Configuration.class)
    @ConditionalOnProperty(name = ENABLED_PROP, havingValue = "true", matchIfMissing = false)
    static @Configuration class Enabled {
        public @PostConstruct void log() {
            log.info("georchestra OAuth2 security enabled");
        }
    }

    @ConditionalOnProperty(name = ENABLED_PROP, havingValue = "false", matchIfMissing = true)
    static @Configuration class Disabled {
        public @PostConstruct void log() {
            log.info("georchestra OAuth2 security disabled");
        }
    }
}
