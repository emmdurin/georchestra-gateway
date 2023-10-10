/*
 * Copyright (C) 2021 by the geOrchestra PSC
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
package org.georchestra.gateway.security.oauth2;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;
import org.georchestra.ds.roles.RoleDao;
import org.georchestra.ds.roles.RoleDaoImpl;
import org.georchestra.ds.roles.RoleProtected;
import org.georchestra.ds.users.AccountDao;
import org.georchestra.ds.users.AccountDaoImpl;
import org.georchestra.gateway.security.ServerHttpSecurityCustomizer;
import org.georchestra.gateway.security.ldap.LdapConfigProperties;
import org.georchestra.gateway.security.ldap.extended.ExtendedLdapConfig;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.condition.ConditionalOnExpression;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Conditional;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.client.reactive.ReactorClientHttpConnector;
import org.springframework.ldap.core.LdapTemplate;
import org.springframework.ldap.core.support.LdapContextSource;
import org.springframework.ldap.pool.factory.PoolingContextSource;
import org.springframework.ldap.pool.validation.DefaultDirContextValidator;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity.OAuth2LoginSpec;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.client.endpoint.ReactiveOAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.WebClientReactiveAuthorizationCodeTokenResponseClient;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcReactiveOAuth2UserService;
import org.springframework.security.oauth2.client.oidc.web.server.logout.OidcClientInitiatedServerLogoutSuccessHandler;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.InMemoryReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.client.userinfo.DefaultReactiveOAuth2UserService;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.BadJwtException;
import org.springframework.security.oauth2.jwt.NimbusReactiveJwtDecoder;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoderFactory;
import org.springframework.security.web.server.authentication.logout.ServerLogoutSuccessHandler;
import org.springframework.web.reactive.function.client.WebClient;

import lombok.extern.slf4j.Slf4j;
import reactor.netty.http.client.HttpClient;
import reactor.netty.transport.ProxyProvider;

import javax.crypto.spec.SecretKeySpec;
import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.util.Arrays;
import java.util.Collections;

import static java.util.Objects.requireNonNull;

@Configuration(proxyBeanMethods = false)
@EnableConfigurationProperties({ OAuth2ProxyConfigProperties.class, OpenIdConnectCustomClaimsConfigProperties.class,
        LdapConfigProperties.class, ExtendedOAuth2ClientProperties.class })
@Slf4j(topic = "org.georchestra.gateway.security.oauth2")
public class OAuth2Configuration {

    public static final class OAuth2AuthenticationCustomizer implements ServerHttpSecurityCustomizer {

        public @Override void customize(ServerHttpSecurity http) {
            log.info("Enabling authentication support using an OAuth 2.0 and/or OpenID Connect 1.0 Provider");
            http.oauth2Login();
        }
    }

    @Bean
    private ServerLogoutSuccessHandler oidcLogoutSuccessHandler(
            InMemoryReactiveClientRegistrationRepository clientRegistrationRepository,
            ExtendedOAuth2ClientProperties properties) {
        OidcClientInitiatedServerLogoutSuccessHandler oidcLogoutSuccessHandler = new OidcClientInitiatedServerLogoutSuccessHandler(
                clientRegistrationRepository);
        clientRegistrationRepository.forEach(client -> {
            if (client.getProviderDetails().getConfigurationMetadata().isEmpty()
                    && properties.getProvider().get(client.getRegistrationId()) != null
                    && properties.getProvider().get(client.getRegistrationId()).getEndSessionUri() != null) {
                try {
                    Field field = ClientRegistration.ProviderDetails.class.getDeclaredField("configurationMetadata");
                    field.setAccessible(true);
                    field.set(client.getProviderDetails(), Collections.singletonMap("end_session_endpoint",
                            properties.getProvider().get(client.getRegistrationId()).getEndSessionUri()));
                } catch (NoSuchFieldException | IllegalAccessException e) {
                    throw new RuntimeException(e);
                }
            }
        });
        oidcLogoutSuccessHandler.setPostLogoutRedirectUri("{baseUrl}/login?logout");

        return oidcLogoutSuccessHandler;
    }

    @Bean
    @ConditionalOnExpression("${georchestra.gateway.security.createNonExistingUsersInLDAP:true} and ${georchestra.gateway.security.ldap.default.enabled:false}")
    public LdapContextSource singleContextSource(LdapConfigProperties config) {
        ExtendedLdapConfig ldapConfig = config.extendedEnabled().get(0);
        LdapContextSource singleContextSource = new LdapContextSource();
        singleContextSource.setUrl(ldapConfig.getUrl());
        singleContextSource.setBase(ldapConfig.getBaseDn());
        singleContextSource.setUserDn(ldapConfig.getAdminDn().get());
        singleContextSource.setPassword(ldapConfig.getAdminPassword().get());
        return singleContextSource;
    }

    @Bean
    @ConditionalOnExpression("${georchestra.gateway.security.createNonExistingUsersInLDAP:true} and ${georchestra.gateway.security.ldap.default.enabled:false}")
    public PoolingContextSource contextSource(LdapConfigProperties config, LdapContextSource singleContextSource) {
        ExtendedLdapConfig ldapConfig = config.extendedEnabled().get(0);
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
    @ConditionalOnExpression("${georchestra.gateway.security.createNonExistingUsersInLDAP:true} and ${georchestra.gateway.security.ldap.default.enabled:false}")
    public LdapTemplate ldapTemplate(PoolingContextSource contextSource) throws Exception {
        LdapTemplate ldapTemplate = new LdapTemplate(contextSource);
        return ldapTemplate;
    }

    @Bean
    @ConditionalOnExpression("${georchestra.gateway.security.createNonExistingUsersInLDAP:true} and  ${georchestra.gateway.security.ldap.default.enabled:false}")
    public RoleDao roleDao(LdapTemplate ldapTemplate, LdapConfigProperties config) {
        RoleDaoImpl impl = new RoleDaoImpl();
        impl.setLdapTemplate(ldapTemplate);
        impl.setRoleSearchBaseDN(config.extendedEnabled().get(0).getRolesRdn());
        return impl;
    }

    @Bean
    @ConditionalOnExpression("${georchestra.gateway.security.createNonExistingUsersInLDAP:true} and ${georchestra.gateway.security.ldap.default.enabled:false}")
    public AccountDao accountDao(LdapTemplate ldapTemplate, LdapConfigProperties config) throws Exception {
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
    @ConditionalOnExpression("${georchestra.gateway.security.createNonExistingUsersInLDAP:true} and ${georchestra.gateway.security.ldap.default.enabled:false}")
    public RoleProtected roleProtected() {
        RoleProtected roleProtected = new RoleProtected();
        roleProtected.setListOfprotectedRoles(
                new String[] { "ADMINISTRATOR", "GN_.*", "ORGADMIN", "REFERENT", "USER", "SUPERUSER" });
        return roleProtected;
    }

    @Bean
    ServerHttpSecurityCustomizer oauth2LoginEnablingCustomizer() {
        return new OAuth2AuthenticationCustomizer();
    }

    @Bean
    OAuth2UserMapper oAuth2GeorchestraUserUserMapper() {
        return new OAuth2UserMapper();
    }

    @Bean
    OpenIdConnectUserMapper openIdConnectGeorchestraUserUserMapper(
            OpenIdConnectCustomClaimsConfigProperties nonStandardClaimsConfig) {
        return new OpenIdConnectUserMapper(nonStandardClaimsConfig);
    }

    /**
     * Configures the OAuth2 client to use the HTTP proxy if enabled, by means of
     * {@linkplain #oauth2WebClient}
     * <p>
     * {@link OAuth2LoginSpec ServerHttpSecurity$OAuth2LoginSpec#createDefault()}
     * will return a {@link ReactiveAuthenticationManager} by first looking up a
     * {@link ReactiveOAuth2AccessTokenResponseClient
     * ReactiveOAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest>}
     * in the application context, and creating a default one if none is found.
     * <p>
     * We provide such bean here to have it configured with an {@link WebClient HTTP
     * client} that will use the {@link OAuth2ProxyConfigProperties configured} HTTP
     * proxy.
     */
    @Bean
    public ReactiveOAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> reactiveOAuth2AccessTokenResponseClient(
            @Qualifier("oauth2WebClient") WebClient oauth2WebClient) {

        WebClientReactiveAuthorizationCodeTokenResponseClient client = new WebClientReactiveAuthorizationCodeTokenResponseClient();
        client.setWebClient(oauth2WebClient);
        return client;
    }

    /**
     * Custom JWT decoder factory to use the web client that can be set up to go
     * through an HTTP proxy
     */
    @Bean
    public ReactiveJwtDecoderFactory<ClientRegistration> idTokenDecoderFactory(
            @Qualifier("oauth2WebClient") WebClient oauth2WebClient) {
        return (clientRegistration) -> (token) -> {
            try {
                JWT jwt = JWTParser.parse(token);
                MacAlgorithm macAlgorithm = MacAlgorithm.from(jwt.getHeader().getAlgorithm().getName());
                if (macAlgorithm != null) {
                    var secretKey = clientRegistration.getClientSecret().getBytes(StandardCharsets.UTF_8);
                    if (secretKey.length < 64) {
                        secretKey = Arrays.copyOf(secretKey, 64);
                    }
                    SecretKeySpec secretKeySpec = new SecretKeySpec(secretKey, macAlgorithm.getName());
                    return NimbusReactiveJwtDecoder.withSecretKey(secretKeySpec).macAlgorithm(macAlgorithm).build()
                            .decode(token);
                }
                return NimbusReactiveJwtDecoder.withJwkSetUri(clientRegistration.getProviderDetails().getJwkSetUri())
                        .webClient(oauth2WebClient).build().decode(token);
            } catch (ParseException exception) {
                throw new BadJwtException(
                        "An error occurred while attempting to decode the Jwt: " + exception.getMessage(), exception);
            }
        };
    }

    @Bean
    public DefaultReactiveOAuth2UserService reactiveOAuth2UserService(
            @Qualifier("oauth2WebClient") WebClient oauth2WebClient) {

        DefaultReactiveOAuth2UserService service = new DefaultReactiveOAuth2UserService();
        service.setWebClient(oauth2WebClient);
        return service;
    };

    @Bean
    public OidcReactiveOAuth2UserService oidcReactiveOAuth2UserService(
            DefaultReactiveOAuth2UserService oauth2Delegate) {
        OidcReactiveOAuth2UserService oidUserService = new OidcReactiveOAuth2UserService();
        oidUserService.setOauth2UserService(oauth2Delegate);
        return oidUserService;
    };

    /**
     * {@link WebClient} to use when performing HTTP POST requests to the OAuth2
     * service providers, that can be configured to use an HTTP proxy through the
     * {@link OAuth2ProxyConfigProperties} configuration properties.
     *
     * @param proxyConfig defines the HTTP proxy settings specific for the OAuth2
     *                    client. If not
     *                    {@link OAuth2ProxyConfigProperties#isEnabled() enabled},
     *                    the {@code WebClient} will use the proxy configured
     *                    through System properties ({@literal http(s).proxyHost}
     *                    and {@literal http(s).proxyPort}), if any.
     */
    @Bean("oauth2WebClient")
    public WebClient oauth2WebClient(OAuth2ProxyConfigProperties proxyConfig) {
        final String proxyHost = proxyConfig.getHost();
        final Integer proxyPort = proxyConfig.getPort();
        final String proxyUser = proxyConfig.getUsername();
        final String proxyPassword = proxyConfig.getPassword();

        HttpClient httpClient = HttpClient.create();
        if (proxyConfig.isEnabled()) {
            if (proxyHost == null || proxyPort == null) {
                throw new IllegalStateException("OAuth2 client HTTP proxy is enabled, but host and port not provided");
            }
            log.info("Oauth2 client will use HTTP proxy {}:{}", proxyHost, proxyPort);
            httpClient = httpClient.proxy(proxy -> proxy.type(ProxyProvider.Proxy.HTTP).host(proxyHost).port(proxyPort)
                    .username(proxyUser).password(user -> {
                        return proxyPassword;
                    }));
        } else {
            log.info("Oauth2 client will use HTTP proxy from System properties if provided");
            httpClient = httpClient.proxyWithSystemProperties();
        }
        ReactorClientHttpConnector conn = new ReactorClientHttpConnector(httpClient);

        WebClient webClient = WebClient.builder().clientConnector(conn).build();
        return webClient;
    }

}
