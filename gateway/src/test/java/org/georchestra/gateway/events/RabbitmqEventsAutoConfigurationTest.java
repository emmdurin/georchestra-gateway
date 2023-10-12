package org.georchestra.gateway.events;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.springframework.amqp.rabbit.connection.CachingConnectionFactory;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

/**
 * Application context test for {@link RabbitmqEventsAutoConfiguration}
 */
class RabbitmqEventsAutoConfigurationTest {

    private ApplicationContextRunner runner = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(RabbitmqEventsAutoConfiguration.class));

    @Test
    void conditionalOnPropertyNotSet() {
        runner.run(context -> assertThat(context).hasNotFailed().doesNotHaveBean(RabbitmqEventsSender.class));
    }

    @Test
    void conditionalOnPropertyDisabled() {
        runner.withPropertyValues("georchestra.gateway.security.enableRabbitmqEvents=false")
                .run(context -> assertThat(context).hasNotFailed().doesNotHaveBean(RabbitmqEventsSender.class));
    }

    @Test
    void conditionalOnPropertyEnabled_requires_default_ldap_and_create_users_enabled() {
        runner.withPropertyValues("georchestra.gateway.security.createNonExistingUsersInLDAP=false", //
                "georchestra.gateway.security.ldap.default.enabled=", //
                "georchestra.gateway.security.enableRabbitmqEvents=true", //
                "rabbitmqHost=test.rabbit", //
                "rabbitmqPort=3333", //
                "rabbitmqUser=bunny", //
                "rabbitmqPassword=rabbit"//
        ).run(context -> assertThat(context).hasNotFailed().doesNotHaveBean(RabbitmqEventsSender.class));

        runner.withPropertyValues("georchestra.gateway.security.createNonExistingUsersInLDAP=true", //
                "georchestra.gateway.security.ldap.default.enabled=true", //
                "georchestra.gateway.security.enableRabbitmqEvents=true", //
                "rabbitmqHost=test.rabbit", //
                "rabbitmqPort=3333", //
                "rabbitmqUser=bunny", //
                "rabbitmqPassword=rabbit"//
        ).run(context -> {

            assertThat(context).hasNotFailed().hasSingleBean(RabbitmqEventsSender.class);

            assertThat(context).hasBean("connectionFactory");
            CachingConnectionFactory rabbitMQConnectionFactory = (CachingConnectionFactory) context
                    .getBean("connectionFactory");
            assertThat(rabbitMQConnectionFactory.getHost()).isEqualTo("test.rabbit");
            assertThat(rabbitMQConnectionFactory.getPort()).isEqualTo(3333);
            assertThat(rabbitMQConnectionFactory.getUsername()).isEqualTo("bunny");
        });
    }
}
