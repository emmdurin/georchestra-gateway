package org.georchestra.gateway.security.preauth;

import org.georchestra.gateway.security.ServerHttpSecurityCustomizer;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.authentication.AuthenticationWebFilter;

public class PreauthGatewaySecurityCustomizer implements ServerHttpSecurityCustomizer {

    @SuppressWarnings("deprecation")
    @Override
    public void customize(ServerHttpSecurity http) {
        PreauthAuthenticationManager authenticationManager = new PreauthAuthenticationManager();
        AuthenticationWebFilter headerFilter = new AuthenticationWebFilter(authenticationManager);

        // return Mono.empty() if preauth headers not provided
        headerFilter.setAuthenticationConverter(authenticationManager::convert);
        http.addFilterAt(headerFilter, SecurityWebFiltersOrder.FIRST);

    }

}
