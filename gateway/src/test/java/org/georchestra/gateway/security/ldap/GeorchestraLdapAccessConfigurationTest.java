package org.georchestra.gateway.security.ldap;

import org.georchestra.ds.orgs.OrgsDao;
import org.georchestra.ds.users.AccountDao;
import org.georchestra.gateway.security.ldap.basic.BasicLdapAuthenticationConfiguration;
import org.junit.jupiter.api.Test;
import org.springframework.boot.context.annotation.UserConfigurations;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Configuration;

import static org.assertj.core.api.Assertions.assertThat;

public class GeorchestraLdapAccessConfigurationTest {

    @EnableConfigurationProperties(LdapConfigProperties.class)
    static @Configuration class EnableConfigProps {
    }

    private ApplicationContextRunner runner = new ApplicationContextRunner()
            .withUserConfiguration(LdapConfigPropertiesValidationsTest.EnableConfigProps.class)
            .withConfiguration(UserConfigurations.of(GeorchestraLdapAccessConfiguration.class));

    public @Test void accountsAndRolesDaoRelatedBeansAreAvailable() {
        runner.withPropertyValues(""//
        // Georchestra extended LDAP default config
                , "georchestra.gateway.security.ldap.default.enabled: true" //
                , "georchestra.gateway.security.ldap.default.extended: true" //
                , "georchestra.gateway.security.ldap.default.adminDn: cn=admin,dc=test,dc=com" //
                , "georchestra.gateway.security.ldap.default.adminPassword: secret" //
                , "georchestra.gateway.security.ldap.default.url: ldap://ldap2.test.com:839" //
                , "georchestra.gateway.security.ldap.default.baseDn: dc=test,dc=com" //
                , "georchestra.gateway.security.ldap.default.users.rdn: ou=users,dc=tes,dc=com" //
                , "georchestra.gateway.security.ldap.default.users.searchFilter: (uid={0})" //
                , "georchestra.gateway.security.ldap.default.roles.rdn: ou=roles" //
                , "georchestra.gateway.security.ldap.default.roles.searchFilter: (member={0})"//
                , "georchestra.gateway.security.ldap.default.orgs.rdn: ou=orgs,dc=tes,dc=com"//
                , "georchestra.gateway.security.createNonExistingUsersInLDAP: true" //

        ).run(context -> {
            assertThat(context).hasNotFailed().hasSingleBean(OrgsDao.class).hasSingleBean(AccountDao.class);
        });
    }
}
