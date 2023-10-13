package org.georchestra.gateway.security.preauth;

import lombok.extern.slf4j.Slf4j;
import org.georchestra.ds.orgs.OrgsDao;
import org.georchestra.ds.users.AccountDao;
import org.georchestra.gateway.app.GeorchestraGatewayApplication;
import org.georchestra.gateway.security.ldap.accounts.CreateNonExistingPreauthUserFilter;
import org.georchestra.gateway.security.ldap.accounts.GeorchestraLdapAccessConfiguration;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.reactive.AutoConfigureWebTestClient;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.ApplicationContext;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.reactive.server.WebTestClient;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * Integration tests for {@link GeorchestraLdapAccessConfiguration} class.
 */
@SpringBootTest(classes = GeorchestraGatewayApplication.class)
@AutoConfigureWebTestClient(timeout = "PT20S")
@ActiveProfiles("preauth")
@Slf4j
public class ResolveHttpHeadersGeorchestraUserFilterIT {

    private @Autowired WebTestClient testClient;

    private @Autowired ApplicationContext context;

    private static final Map<String, String> ADMIN_HEADERS = Map.of("sec-georchestra-preauthenticated", "true",
            "sec-username", "pmartin", "sec-email", "pierre.martin@example.org", "sec-firstname", "Pierre",
            "sec-lastname", "Martin", "sec-org", "C2C", "Accept", "application/json");

    private WebTestClient.RequestHeadersUriSpec<?> prepareWebTestClientHeaders(
            WebTestClient.RequestHeadersUriSpec<?> spec, Map<String, String> headers) {
        headers.forEach((k, v) -> {
            spec.header(k, v);
        });
        return spec;
    }

    public @Test void test_preauthenticatedHeadersAccess() {
        assertNotNull(context.getBean(OrgsDao.class));
        assertNotNull(context.getBean(AccountDao.class));
        assertNotNull(context.getBean(ResolveHttpHeadersGeorchestraUserFilter.class));
        assertNotNull(context.getBean(CreateNonExistingPreauthUserFilter.class));

        prepareWebTestClientHeaders(testClient.get(), ADMIN_HEADERS).uri("/whoami")//
                .exchange()//
                .expectStatus().is2xxSuccessful().expectBody().jsonPath("$.GeorchestraUser").isNotEmpty();

    }

}
