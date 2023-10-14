package org.georchestra.gateway.filter.headers;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.List;

import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.cloud.gateway.route.Route;
import org.springframework.cloud.gateway.support.ServerWebExchangeUtils;
import org.springframework.http.server.reactive.ServerHttpRequest;

public class ProxyGatewayFilterFactory extends AbstractGatewayFilterFactory<Object> {
    public ProxyGatewayFilterFactory() {
        super(Object.class);
    }

    @Override
    public GatewayFilter apply(final Object config) {
        return (exchange, chain) -> {
            Route route = exchange.getAttribute(ServerWebExchangeUtils.GATEWAY_ROUTE_ATTR);
            ServerHttpRequest request = exchange.getRequest();
            List<String> urls = request.getQueryParams().get("url");
            if ((urls != null) && (urls.size() == 1)) {
                try {
                    request = exchange.getRequest().mutate().uri(new URI(urls.get(0))).build();

                    Route newRoute = Route.async().id(route.getId()).uri(new URI(urls.get(0))).order(route.getOrder())
                            .asyncPredicate(route.getPredicate()).build();

                    exchange.getAttributes().put(AddSecHeadersGatewayFilterFactory.DISABLE_SECURITY_HEADERS, "true");
                    exchange.getAttributes().put(ServerWebExchangeUtils.GATEWAY_ROUTE_ATTR, newRoute);
                    return chain.filter(exchange.mutate().request(request).build());
                } catch (URISyntaxException e) {
                }
            }
            return chain.filter(exchange);
        };
    }
}
