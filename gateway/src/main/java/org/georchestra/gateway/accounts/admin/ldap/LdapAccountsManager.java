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

import java.util.Optional;
import java.util.function.Consumer;

import org.georchestra.ds.DataServiceException;
import org.georchestra.ds.DuplicatedCommonNameException;
import org.georchestra.ds.roles.RoleDao;
import org.georchestra.ds.roles.RoleFactory;
import org.georchestra.ds.users.Account;
import org.georchestra.ds.users.AccountDao;
import org.georchestra.ds.users.AccountFactory;
import org.georchestra.ds.users.DuplicatedEmailException;
import org.georchestra.ds.users.DuplicatedUidException;
import org.georchestra.gateway.accounts.admin.AbstractAccountsManager;
import org.georchestra.gateway.accounts.admin.AccountCreated;
import org.georchestra.gateway.accounts.admin.AccountManager;
import org.georchestra.security.api.UsersApi;
import org.georchestra.security.model.GeorchestraUser;
import org.springframework.ldap.NameNotFoundException;

import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;

/**
 * {@link AccountManager} that fetches and creates {@link GeorchestraUser}s from
 * the Georchestra extended LDAP service provided by an {@link AccountDao} and
 * {@link RoleDao}.
 */
@Slf4j(topic = "org.georchestra.gateway.accounts.admin.ldap")
class LdapAccountsManager extends AbstractAccountsManager {

    private final @NonNull AccountDao accountDao;
    private final @NonNull RoleDao roleDao;
    private final @NonNull UsersApi usersApi;

    public LdapAccountsManager(Consumer<AccountCreated> eventPublisher, AccountDao accountDao, RoleDao roleDao,
            UsersApi usersApi) {
        super(eventPublisher);
        this.accountDao = accountDao;
        this.roleDao = roleDao;
        this.usersApi = usersApi;
    }

    @Override
    protected Optional<GeorchestraUser> findByOAuth2ProviderId(@NonNull String oauth2ProviderId) {
        return usersApi.findByOAuth2ProviderId(oauth2ProviderId);
    }

    @Override
    protected Optional<GeorchestraUser> findByUsername(@NonNull String username) {
        return usersApi.findByUsername(username);
    }

    @Override
    protected void createInternal(GeorchestraUser mapped) {
        Account newAccount = mapToAccountBrief(mapped);
        try {
            accountDao.insert(newAccount);
        } catch (DataServiceException | DuplicatedUidException | DuplicatedEmailException accountError) {
            throw new IllegalStateException(accountError);
        }

        try {// account created, add roles
            if (!mapped.getRoles().contains("ROLE_USER")) {
                roleDao.addUser("ROLE_USER", newAccount);
            }
            for (String role : mapped.getRoles()) {
                role = role.replaceFirst("^ROLE_", "");
                ensureRoleExists(role);
                roleDao.addUser(role, newAccount);
            }
        } catch (NameNotFoundException | DataServiceException roleError) {
            try {// roll-back account
                accountDao.delete(newAccount);
            } catch (NameNotFoundException | DataServiceException rolbackError) {
                log.warn("Error reverting user creation after roleDao update failure", rolbackError);
            }
            throw new IllegalStateException(roleError);
        }
    }

    private void ensureRoleExists(String role) throws DataServiceException {
        try {
            roleDao.findByCommonName(role);
        } catch (NameNotFoundException notFound) {
            try {
                roleDao.insert(RoleFactory.create(role, null, null));
            } catch (DuplicatedCommonNameException e) {
                throw new IllegalStateException(e);
            }
        }
    }

    private Account mapToAccountBrief(@NonNull GeorchestraUser preAuth) {
        String username = preAuth.getUsername();
        String email = preAuth.getEmail();
        String firstName = preAuth.getFirstName();
        String lastName = preAuth.getLastName();
        String org = preAuth.getOrganization();
        String password = null;
        String phone = "";
        String title = "";
        String description = "";
        final @javax.annotation.Nullable String oAuth2ProviderId = preAuth.getOAuth2ProviderId();

        Account newAccount = AccountFactory.createBrief(username, password, firstName, lastName, email, phone, title,
                description, oAuth2ProviderId);
        newAccount.setPending(false);
        newAccount.setOrg(org);
        return newAccount;
    }
}
