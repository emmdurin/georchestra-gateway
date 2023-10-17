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
package org.georchestra.gateway.accounts.admin.ldap;

import static java.util.Objects.requireNonNull;

import java.util.Collections;
import java.util.List;

import org.georchestra.ds.orgs.OrgsDao;
import org.georchestra.ds.orgs.OrgsDaoImpl;
import org.georchestra.ds.roles.RoleDao;
import org.georchestra.ds.roles.RoleDaoImpl;
import org.georchestra.ds.roles.RoleProtected;
import org.georchestra.ds.security.UserMapperImpl;
import org.georchestra.ds.security.UsersApiImpl;
import org.georchestra.ds.users.AccountDao;
import org.georchestra.ds.users.AccountDaoImpl;
import org.georchestra.ds.users.UserRule;
import org.georchestra.gateway.accounts.admin.AccountManager;
import org.georchestra.gateway.accounts.admin.CreateAccountUserCustomizer;
import org.georchestra.gateway.security.ldap.LdapConfigProperties;
import org.georchestra.gateway.security.ldap.extended.ExtendedLdapConfig;
import org.georchestra.security.api.UsersApi;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.ldap.core.LdapTemplate;
import org.springframework.ldap.core.support.LdapContextSource;
import org.springframework.ldap.pool.factory.PoolingContextSource;
import org.springframework.ldap.pool.validation.DefaultDirContextValidator;

@Configuration(proxyBeanMethods = false)
@EnableConfigurationProperties(LdapConfigProperties.class)
public class GeorchestraLdapAccountManagementConfiguration {

    @Bean
    AccountManager ldapAccountsManager(//
            ApplicationEventPublisher eventPublisher, //
            AccountDao accountDao, RoleDao roleDao, OrgsDao orgsDao) {

        UsersApi usersApi = ldapUsersApi(accountDao, roleDao);
        return new LdapAccountsManager(eventPublisher::publishEvent, accountDao, roleDao, orgsDao, usersApi);
    }

    @Bean
    CreateAccountUserCustomizer createAccountUserCustomizer(AccountManager accountManager) {
        return new CreateAccountUserCustomizer(accountManager);
    }

    private UsersApi ldapUsersApi(AccountDao accountDao, RoleDao roleDao) {
        UserMapperImpl mapper = new UserMapperImpl();
        mapper.setRoleDao(roleDao);
        List<String> protectedUsers = Collections.emptyList();
        UserRule rule = new UserRule();
        rule.setListOfprotectedUsers(protectedUsers.toArray(String[]::new));
        UsersApiImpl usersApi = new UsersApiImpl();
        usersApi.setAccountsDao(accountDao);
        usersApi.setMapper(mapper);
        usersApi.setUserRule(rule);
        return usersApi;
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
    PoolingContextSource contextSource(LdapContextSource singleContextSource) {
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
        ExtendedLdapConfig ldapConfig = config.extendedEnabled().get(0);
        impl.setBasePath(ldapConfig.getBaseDn());
        impl.setOrgSearchBaseDN(ldapConfig.getOrgsRdn());
        impl.setPendingOrgSearchBaseDN(ldapConfig.getPendingOrgsRdn());
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
