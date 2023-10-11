package org.georchestra.gateway.security.ldap.accounts;

import static java.util.Objects.requireNonNull;

import org.georchestra.ds.orgs.OrgsDao;
import org.georchestra.ds.orgs.OrgsDaoImpl;
import org.georchestra.ds.roles.RoleDao;
import org.georchestra.ds.roles.RoleDaoImpl;
import org.georchestra.ds.roles.RoleProtected;
import org.georchestra.ds.users.AccountDao;
import org.georchestra.ds.users.AccountDaoImpl;
import org.georchestra.gateway.security.ldap.LdapConfigProperties;
import org.georchestra.gateway.security.ldap.extended.ExtendedLdapConfig;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.ldap.core.LdapTemplate;
import org.springframework.ldap.core.support.LdapContextSource;
import org.springframework.ldap.pool.factory.PoolingContextSource;
import org.springframework.ldap.pool.validation.DefaultDirContextValidator;

@Configuration(proxyBeanMethods = false)
@EnableConfigurationProperties(LdapConfigProperties.class)
public class GeorchestraLdapAccessConfiguration {

    /**
     * Filter to create LDAP accounts if pre-authentication and the default LDAP
     * database are enabled
     */
    @Bean
    CreateNonExistingPreauthUserFilter createNonExistingPreauthUserFilter(LdapConfigProperties config,
            AccountDao accountDao, RoleDao roleDao) {
        return new CreateNonExistingPreauthUserFilter(config, accountDao, roleDao);
    }

    @Bean
    LdapContextSource singleContextSource(LdapConfigProperties config) {
        ExtendedLdapConfig ldapConfig = config.extendedEnabled().get(0);
        LdapContextSource singleContextSource = new LdapContextSource();
        singleContextSource.setUrl(ldapConfig.getUrl());
        singleContextSource.setBase(ldapConfig.getBaseDn());
        singleContextSource.setUserDn(ldapConfig.getAdminDn().get());
        singleContextSource.setPassword(ldapConfig.getAdminPassword().get());
        return singleContextSource;
    }

    @Bean
    PoolingContextSource contextSource(LdapConfigProperties config, LdapContextSource singleContextSource) {
        PoolingContextSource contextSource = new PoolingContextSource();
        contextSource.setContextSource(singleContextSource);
        contextSource.setDirContextValidator(new DefaultDirContextValidator());
        contextSource.setTestOnBorrow(true);
        contextSource.setMaxActive(8);
        contextSource.setMinIdle(1);
        contextSource.setMaxIdle(8);
        contextSource.setMaxTotal(-1);
        contextSource.setMaxWait(-1);
        return contextSource;
    }

    @Bean
    LdapTemplate ldapTemplate(PoolingContextSource contextSource) throws Exception {
        LdapTemplate ldapTemplate = new LdapTemplate(contextSource);
        return ldapTemplate;
    }

    @Bean
    RoleDao roleDao(LdapTemplate ldapTemplate, LdapConfigProperties config) {
        RoleDaoImpl impl = new RoleDaoImpl();
        impl.setLdapTemplate(ldapTemplate);
        impl.setRoleSearchBaseDN(config.extendedEnabled().get(0).getRolesRdn());
        return impl;
    }

    @Bean
    OrgsDao orgsDao(LdapTemplate ldapTemplate, LdapConfigProperties config) {
        OrgsDaoImpl impl = new OrgsDaoImpl();
        impl.setLdapTemplate(ldapTemplate);
        impl.setOrgSearchBaseDN(config.extendedEnabled().get(0).getOrgsRdn());
        return impl;
    }

    @Bean
    AccountDao accountDao(LdapTemplate ldapTemplate, LdapConfigProperties config) throws Exception {
        ExtendedLdapConfig ldapConfig = config.extendedEnabled().get(0);
        String baseDn = ldapConfig.getBaseDn();
        String userSearchBaseDN = ldapConfig.getUsersRdn();
        String roleSearchBaseDN = ldapConfig.getRolesRdn();

        // we don't need a configuration property for this,
        // we don't allow pending users to log in. The LdapAuthenticationProvider won't
        // even look them up.
        final String pendingUsersSearchBaseDN = "ou=pendingusers";

        AccountDaoImpl impl = new AccountDaoImpl(ldapTemplate);
        impl.setBasePath(baseDn);
        impl.setUserSearchBaseDN(userSearchBaseDN);
        impl.setRoleSearchBaseDN(roleSearchBaseDN);
        if (pendingUsersSearchBaseDN != null) {
            impl.setPendingUserSearchBaseDN(pendingUsersSearchBaseDN);
        }

        String orgSearchBaseDN = ldapConfig.getOrgsRdn();
        requireNonNull(orgSearchBaseDN);
        impl.setOrgSearchBaseDN(orgSearchBaseDN);

        // not needed here, only console cares, we shouldn't allow to authenticate
        // pending users, should we?
        final String pendingOrgSearchBaseDN = "ou=pendingorgs";
        impl.setPendingOrgSearchBaseDN(pendingOrgSearchBaseDN);

        impl.init();
        return impl;
    }

    @Bean
    RoleProtected roleProtected() {
        RoleProtected roleProtected = new RoleProtected();
        roleProtected.setListOfprotectedRoles(
                new String[] { "ADMINISTRATOR", "GN_.*", "ORGADMIN", "REFERENT", "USER", "SUPERUSER" });
        return roleProtected;
    }
}
