package org.georchestra.gateway.autoconfigure.security;

import org.georchestra.gateway.security.preauth.ResolveHttpHeadersGeorchestraUserFilter;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

import static org.assertj.core.api.Assertions.assertThat;

public class PreAuthenticationAutoConfigurationTest {
    private ApplicationContextRunner runner = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(PreAuthenticationAutoConfiguration.class));

    public @Test void resolveHttpHeadersGeorchestraUserFilterIsAvailable() {
        runner.withPropertyValues(""//
                , "georchestra.gateway.headerAuthentication: true" //
        ).run(context -> {
            assertThat(context).hasNotFailed().hasSingleBean(ResolveHttpHeadersGeorchestraUserFilter.class);
        });
    }

    public @Test void resolveHttpHeadersGeorchestraUserFilterIsUnavailable() {
        runner.withPropertyValues(""//
                , "georchestra.gateway.headerAuthentication: false" //
        ).run(context -> {
            assertThat(context).hasNotFailed().doesNotHaveBean(ResolveHttpHeadersGeorchestraUserFilter.class);
        });
    }
}
