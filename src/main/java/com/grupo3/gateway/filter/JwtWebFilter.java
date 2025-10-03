package com.grupo3.gateway.filter;

import com.grupo3.gateway.service.ITokenService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

import java.util.List;

@Component
@RequiredArgsConstructor
public class JwtWebFilter implements WebFilter {
    private final ITokenService tokenService;

    @Value("${app.public-patterns}")
    private String publicUrls;

    private List<String> splitPublicUrls(){
        return List.of(publicUrls.split(","))
                .stream()
                .map(String::trim)
                .map(s -> s.replaceAll("^\"|\"$", "").replaceAll("^'|'$", ""))
                .filter(s -> !s.isEmpty())
                .toList();
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        String path = exchange.getRequest().getPath().value();

        List<String> urls = splitPublicUrls();

        // Omitir endpoints públicos (usa patrones ANT como "/api/auth/**")
        AntPathMatcher matcher = new AntPathMatcher();
        if (urls.stream()
                .map(String::trim)
                .filter(s -> !s.isEmpty())
                .anyMatch(pattern -> matcher.match(pattern, path))) {
            return chain.filter(exchange);
        }

        // Permitir preflight CORS sin autenticación
        HttpMethod method = exchange.getRequest().getMethod();
        if (org.springframework.http.HttpMethod.OPTIONS.equals(method)) {
            return chain.filter(exchange);
        }

        // Extraer token
        String token = extractToken(exchange.getRequest());

        if(token == null){
            return onError(exchange, HttpStatus.UNAUTHORIZED);
        }
        try{
            tokenService.validateToken(token);
            return authenticateAndMutate(exchange, chain, token);
        } catch (ResponseStatusException e) {
            // Captura las excepciones de validación lanzadas por validateToken()
            return onError(exchange, HttpStatus.valueOf(e.getStatusCode().value()));
        } catch (Exception e) {
            // Captura errores de firma, I/O, etc. (lanzados internamente por extractClaim)
            return onError(exchange, HttpStatus.UNAUTHORIZED);
        }
    }
    private Mono<Void> onError(ServerWebExchange exchange, HttpStatus status) {
        exchange.getResponse().setStatusCode(status);

        exchange.getResponse().getHeaders().setContentType(MediaType.APPLICATION_JSON);

        String errorMessage = String.format("{\"error\": \"%s\", \"message\": \"Authentication failed: Invalid or missing JWT.\"}", status.getReasonPhrase());

        return exchange.getResponse().writeWith(
                Mono.just(exchange.getResponse().bufferFactory().wrap(errorMessage.getBytes()))
        );
    }

    private Mono<Void> authenticateAndMutate(ServerWebExchange exchange, WebFilterChain chain, String token) {
        // Obtenemos el username de forma segura (asumiendo que validateToken() pasó)
        String username = tokenService.extractUsername(token);

        Authentication auth = new UsernamePasswordAuthenticationToken(username, null);

        // Mutar la solicitud: Añadir el username a un header para los microservicios
        ServerWebExchange mutatedExchange = exchange.mutate()
                .request(request -> request.header("X-Auth-User", username))
                .build();

        // Continuar la cadena y establecer el contexto
        return chain.filter(mutatedExchange)
                .contextWrite(ReactiveSecurityContextHolder.withAuthentication(auth));
    }

    private String extractToken(ServerHttpRequest request) {
        // 1. Obtener el valor del encabezado 'Authorization'.
        // Usamos getFirst() porque solo debe haber un encabezado de autorización.
        String authHeader = request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);

        // 2. Verificar que el encabezado existe y comienza con "Bearer ".
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            // 3. Devolver la cadena del token, quitando el prefijo "Bearer " (que tiene 7 caracteres, incluyendo el espacio).
            return authHeader.substring(7);
        }

        // 4. Si el encabezado no existe o no tiene el formato correcto, devolver null.
        return null;
    }
}
