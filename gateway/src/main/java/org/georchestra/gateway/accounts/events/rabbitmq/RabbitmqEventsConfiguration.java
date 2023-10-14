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
package org.georchestra.gateway.accounts.events.rabbitmq;

import org.springframework.amqp.core.AmqpTemplate;
import org.springframework.amqp.rabbit.connection.CachingConnectionFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.ImportResource;

/**
 * {@link Configuration @Configuration} to enable sending events over rabbitmq
 * 
 */
@Configuration
@ImportResource({ "classpath:rabbit-listener-context.xml", "classpath:rabbit-sender-context.xml" })
public class RabbitmqEventsConfiguration {

    @Bean
    RabbitmqAccountCreatedEventSender eventsSender(@Qualifier("eventTemplate") AmqpTemplate eventTemplate) {
        return new RabbitmqAccountCreatedEventSender(eventTemplate);
    }

    @Bean
    org.springframework.amqp.rabbit.connection.CachingConnectionFactory connectionFactory(//
            @Value("${rabbitmqHost}") String host, //
            @Value("${rabbitmqPort}") int port, //
            @Value("${rabbitmqUser}") String user, //
            @Value("${rabbitmqPassword}") String pwd) {

        com.rabbitmq.client.ConnectionFactory fac = new com.rabbitmq.client.ConnectionFactory();
        fac.setHost(host);
        fac.setPort(port);
        fac.setUsername(user);
        fac.setPassword(pwd);

        return new CachingConnectionFactory(fac);
    }
}
