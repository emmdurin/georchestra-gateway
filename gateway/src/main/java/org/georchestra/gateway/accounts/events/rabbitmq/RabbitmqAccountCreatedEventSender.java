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

import java.util.UUID;

import org.georchestra.gateway.accounts.admin.AccountCreated;
import org.georchestra.security.model.GeorchestraUser;
import org.json.JSONObject;
import org.springframework.amqp.core.AmqpTemplate;
import org.springframework.context.event.EventListener;

/**
 * Service bean that listens to {@link AccountCreated} events and publish a
 * distributed event through rabbitmq to the {@literal OAUTH2-ACCOUNT-CREATION}
 * queue.
 */
public class RabbitmqAccountCreatedEventSender {

    public static final String OAUTH2_ACCOUNT_CREATION = "OAUTH2-ACCOUNT-CREATION";

    private AmqpTemplate eventTemplate;

    public RabbitmqAccountCreatedEventSender(AmqpTemplate eventTemplate) {
        this.eventTemplate = eventTemplate;
    }

    @EventListener(AccountCreated.class)
    public void on(AccountCreated event) {
        GeorchestraUser user = event.getUser();
        final String oAuth2ProviderId = user.getOAuth2ProviderId();
        if (null != oAuth2ProviderId) {
            String fullName = user.getFirstName() + " " + user.getLastName();
            String email = user.getEmail();
            String provider = oAuth2ProviderId;
            sendNewOAuthAccountMessage(fullName, email, provider);
        }
    }

    public void sendNewOAuthAccountMessage(String fullName, String email, String provider) {
        // beans getting a reference to the sender
        JSONObject jsonObj = new JSONObject();
        jsonObj.put("uid", UUID.randomUUID());
        jsonObj.put("subject", OAUTH2_ACCOUNT_CREATION);
        jsonObj.put("username", fullName); // bean
        jsonObj.put("email", email); // bean
        jsonObj.put("provider", provider); // bean
        eventTemplate.convertAndSend("routing-gateway", jsonObj.toString());// send
    }
}