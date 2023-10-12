package org.georchestra.gateway.events;

import org.georchestra.gateway.autoconfigure.security.ConditionalOnCreateLdapAccounts;
import org.springframework.amqp.core.AmqpTemplate;
import org.springframework.amqp.rabbit.connection.CachingConnectionFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.AutoConfigureAfter;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.cloud.gateway.config.GatewayAutoConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ImportResource;

/**
 * {@link AutoConfiguration @AutoConfiguration} to enable sending events over
 * rabbitmq when it is enabled to create LDAP accounts from both/either
 * pre-authenticated and OIDC authentication scenarios, AND
 * {@literal georchestra.gateway.security.enableRabbitmqEvents = true}
 * 
 * @see ConditionalOnCreateLdapAccounts
 */
@AutoConfiguration
@ConditionalOnCreateLdapAccounts
@AutoConfigureAfter(GatewayAutoConfiguration.class)
@ImportResource({ "classpath:rabbit-listener-context.xml", "classpath:rabbit-sender-context.xml" })
@ConditionalOnProperty(name = "georchestra.gateway.security.enableRabbitmqEvents", havingValue = "true", matchIfMissing = false)
public class RabbitmqEventsAutoConfiguration {

    @Bean
    RabbitmqEventsSender eventsSender(@Qualifier("eventTemplate") AmqpTemplate eventTemplate) {
        return new RabbitmqEventsSender(eventTemplate);
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
