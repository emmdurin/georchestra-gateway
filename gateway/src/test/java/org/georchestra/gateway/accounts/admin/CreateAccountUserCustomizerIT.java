package org.georchestra.gateway.accounts.admin;

import org.georchestra.ds.users.AccountDao;
import org.georchestra.gateway.app.GeorchestraGatewayApplication;
import org.georchestra.testcontainers.ldap.GeorchestraLdapContainer;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
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
 * Integration tests for {@link CreateAccountUserCustomizer}.
 */
@SpringBootTest(classes = GeorchestraGatewayApplication.class)
@AutoConfigureWebTestClient(timeout = "PT20S")
@ActiveProfiles("createaccount")
public class CreateAccountUserCustomizerIT {
    private @Autowired WebTestClient testClient;

    private @Autowired ApplicationContext context;

    private @Autowired AccountDao accountDao;

    public static GeorchestraLdapContainer ldap = new GeorchestraLdapContainer();

    public static @BeforeAll void startUpContainers() {
        ldap.start();
    }

    public static @AfterAll void shutDownContainers() {
        ldap.stop();
    }

    private static final Map<String, String> NOT_EXISTING_ACCOUNT_HEADERS = Map.of( //
            "sec-georchestra-preauthenticated", "true", //
            "preauth-username", "pmartin", //
            "preauth-email", "pierre.martin@example.org", //
            "preauth-firstname", "Pierre", //
            "preauth-lastname", "Martin", //
            "preauth-org", "C2C");

    private static final Map<String, String> EXISTING_ADMIN_ACCOUNT_HEADERS = Map.of( //
            "sec-georchestra-preauthenticated", "true", //
            "preauth-username", "testadmin", //
            "preauth-email", "psc+testadmin@georchestra.org", //
            "preauth-firstname", "Admin", //
            "preauth-lastname", "Test", //
            "preauth-org", "GEORCHESTRA");

    private WebTestClient.RequestHeadersUriSpec<?> prepareWebTestClientHeaders(
            WebTestClient.RequestHeadersUriSpec<?> spec, Map<String, String> headers) {
        headers.forEach((k, v) -> {
            spec.header(k, v);
        });
        return spec;
    }

    public @Test void testPreauthenticatedHeadersAccess() throws Exception {
        prepareWebTestClientHeaders(testClient.get(), NOT_EXISTING_ACCOUNT_HEADERS).uri("/whoami")//
                .exchange()//
                .expectStatus()//
                .is2xxSuccessful()//
                .expectBody()//
                .jsonPath("$.GeorchestraUser").isNotEmpty();

        // Make sure the account has been created
        assertNotNull(accountDao.findByUID("pmartin"));
    }

    public @Test void testPreauthenticatedHeadersAccessExistingAccount() throws Exception {
        // the account should already exist before issuing the request
        assertNotNull(accountDao.findByUID("testadmin"));
        prepareWebTestClientHeaders(testClient.get(), EXISTING_ADMIN_ACCOUNT_HEADERS).uri("/whoami")//
                .exchange()//
                .expectStatus()//
                .is2xxSuccessful()//
                .expectBody()//
                .jsonPath("$.GeorchestraUser").isNotEmpty()//
                .jsonPath("$.GeorchestraUser.roles").value(Matchers.contains("ADMINISTRATOR", "SUPERUSER", "GN_ADMIN",
                        "USER", "MAPSTORE_ADMIN", "EMAILPROXY"));
    }
}
