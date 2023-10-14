package org.georchestra.gateway.autoconfigure.security;

import static org.assertj.core.api.Assertions.assertThat;

import org.georchestra.gateway.security.preauth.PreauthGatewaySecurityCustomizer;
import org.georchestra.gateway.security.preauth.PreauthenticatedUserMapperExtension;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

public class HeaderPreAuthenticationAutoConfigurationTest {
    private ApplicationContextRunner runner = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(HeaderPreAuthenticationAutoConfiguration.class));

    public @Test void resolveHttpHeadersGeorchestraUserFilterIsAvailable() {
        runner.withPropertyValues(""//
                , "georchestra.gateway.security.header-authentication.enabled: true" //
        ).run(context -> {
            assertThat(context).hasNotFailed().hasSingleBean(PreauthGatewaySecurityCustomizer.class)
                    .hasSingleBean(PreauthenticatedUserMapperExtension.class);
        });
    }

    public @Test void resolveHttpHeadersGeorchestraUserFilterIsUnavailable() {
        runner.withPropertyValues(""//
                , "georchestra.gateway.security.header-authentication.enabled: false" //
        ).run(context -> {
            assertThat(context).hasNotFailed().doesNotHaveBean(PreauthGatewaySecurityCustomizer.class)
                    .doesNotHaveBean(PreauthenticatedUserMapperExtension.class);
        });
    }
}
