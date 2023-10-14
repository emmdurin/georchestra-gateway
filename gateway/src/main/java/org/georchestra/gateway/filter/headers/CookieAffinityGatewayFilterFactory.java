package org.georchestra.gateway.filter.headers;

import javax.validation.constraints.NotEmpty;

import org.georchestra.gateway.filter.global.ResolveTargetGlobalFilter;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.core.Ordered;
import org.springframework.http.ResponseCookie;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.server.ServerWebExchange;

import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.Setter;
import reactor.core.publisher.Mono;

public class CookieAffinityGatewayFilterFactory
        extends AbstractGatewayFilterFactory<CookieAffinityGatewayFilterFactory.CookieAffinity> {
    public CookieAffinityGatewayFilterFactory() {
        super(CookieAffinityGatewayFilterFactory.CookieAffinity.class);
    }

    @Override
    public GatewayFilter apply(final CookieAffinityGatewayFilterFactory.CookieAffinity config) {
        return new CookieAffinityGatewayFilter(config);
    }

    @Validated
    public static class CookieAffinity {
        private @NotEmpty @Getter @Setter String name;
        private @NotEmpty @Getter @Setter String from;
        private @NotEmpty @Getter @Setter String to;
    }

    @RequiredArgsConstructor
    private static class CookieAffinityGatewayFilter implements GatewayFilter, Ordered {

        private final CookieAffinity config;

        public @Override Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
            return chain.filter(exchange).then(Mono.fromRunnable(() -> {
                exchange.getResponse().getHeaders().getValuesAsList("Set-Cookie").stream()
                        .flatMap(c -> java.net.HttpCookie.parse(c).stream())
                        .filter(cookie -> cookie.getName().equals(config.getName())
                                && cookie.getPath().equals(config.getFrom()))
                        .forEach(cookie -> {
                            ResponseCookie responseCookie = ResponseCookie.from(cookie.getName(), cookie.getValue())
                                    .domain(cookie.getDomain()).httpOnly(cookie.isHttpOnly()).secure(cookie.getSecure())
                                    .maxAge(cookie.getMaxAge()).path(config.getTo()).build();
                            exchange.getResponse().addCookie(responseCookie);
                        });
            }));
        }

        @Override
        public int getOrder() {
            return ResolveTargetGlobalFilter.ORDER + 1;
        }
    }
}
