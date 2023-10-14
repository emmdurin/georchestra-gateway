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
package org.georchestra.gateway.autoconfigure.accounts;

import org.georchestra.gateway.accounts.events.rabbitmq.RabbitmqEventsConfiguration;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Import;

/**
 * {@link AutoConfiguration @AutoConfiguration} to enable sending events over
 * rabbitmq when it is enabled to create LDAP accounts from both/either
 * pre-authenticated and OIDC authentication scenarios, AND
 * {@literal georchestra.gateway.security.enableRabbitmqEvents = true}
 * 
 * @see ConditionalOnCreateLdapAccounts
 * @see RabbitmqEventsConfiguration
 */
@AutoConfiguration
@ConditionalOnCreateLdapAccounts
@ConditionalOnProperty(name = "georchestra.gateway.security.enableRabbitmqEvents", havingValue = "true", matchIfMissing = false)
@Import(RabbitmqEventsConfiguration.class)
public class RabbitmqEventsAutoConfiguration {
}
