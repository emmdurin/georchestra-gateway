package org.georchestra.gateway.events;

import org.springframework.amqp.core.AmqpTemplate;
import org.springframework.amqp.core.Queue;
import org.springframework.amqp.rabbit.connection.ConnectionFactory;
import org.springframework.amqp.rabbit.listener.MessageListenerContainer;
import org.springframework.amqp.rabbit.listener.SimpleMessageListenerContainer;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.AutoConfigureAfter;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.cloud.gateway.config.GatewayAutoConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.DependsOn;
import org.springframework.context.annotation.ImportResource;
import org.springframework.context.annotation.Profile;

@Profile("!test && !it")
@AutoConfiguration
@AutoConfigureAfter(GatewayAutoConfiguration.class)
@ImportResource({ "classpath:rabbit-listener-context.xml", "classpath:rabbit-sender-context.xml" })
@ConditionalOnProperty(name = "georchestra.gateway.security.enableRabbitmqEvents", havingValue = "true", matchIfMissing = false)
public class RabbitmqEventsAutoConfiguration {

    @Bean
    @DependsOn({ "eventTemplate" })
    RabbitmqEventsSender eventsSender(AmqpTemplate eventTemplate) {
        return new RabbitmqEventsSender(eventTemplate);
    }

    Queue OAuth2ReplyQueue() {
        return new Queue("OAuth2ReplyQueue", false);
    }

    MessageListenerContainer messageListenerContainer(ConnectionFactory connectionFactory) {
        SimpleMessageListenerContainer simpleMessageListenerContainer = new SimpleMessageListenerContainer();
        simpleMessageListenerContainer.setConnectionFactory(connectionFactory);
        simpleMessageListenerContainer.setQueues(OAuth2ReplyQueue());
        simpleMessageListenerContainer.setMessageListener(new RabbitmqEventsListener());
        return simpleMessageListenerContainer;
    }
}