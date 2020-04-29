package com.jdriven.gateway;

import org.springframework.security.oauth2.client.web.server.ServerAuthorizationRequestRepository;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

public class RedisAuthRequestRepository implements ServerAuthorizationRequestRepository<OAuth2AuthorizationRequest> {
    @Override
    public Mono<OAuth2AuthorizationRequest> loadAuthorizationRequest(ServerWebExchange serverWebExchange) {
        return null;
    }

    @Override
    public Mono<Void> saveAuthorizationRequest(OAuth2AuthorizationRequest oAuth2AuthorizationRequest,
                                               ServerWebExchange serverWebExchange) {
        return null;
    }

    @Override
    public Mono<OAuth2AuthorizationRequest> removeAuthorizationRequest(ServerWebExchange serverWebExchange) {
        return null;
    }
}
