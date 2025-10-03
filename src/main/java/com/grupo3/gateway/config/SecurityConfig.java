package com.grupo3.gateway.config;

import com.grupo3.gateway.filter.JwtWebFilter;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.context.NoOpServerSecurityContextRepository;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.CorsConfigurationSource;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;

import java.util.List;
import java.util.stream.Stream;

@Slf4j
@Configuration
@EnableWebFluxSecurity
@RequiredArgsConstructor
public class SecurityConfig {
    private final JwtWebFilter jwtWebFilter;

    @Value("${app.public-patterns}")
    private String publicPatterns;

    @Value("${app.cors.allowed-origins}")
    private String allowedOrigins;

    @Bean
    public CorsConfigurationSource corsConfigurationSource(){
        CorsConfiguration config = new CorsConfiguration();

        String[] origins = allowedOrigins.split(",");

        config.setAllowedOrigins(List.of(origins));
        config.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS"));
        config.setAllowedHeaders(List.of("Content-Type", "Authorization", "X-Requested-With", "Accept", "Origin"));
        config.setAllowCredentials(true);
        config.setExposedHeaders(List.of("Authorization"));
        config.setMaxAge(3600L);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);

        return source;
    }

    @Bean
    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http){
        String[] publicRoutes = Stream.of(publicPatterns.split(","))
                .map(String::trim)
                .map(s -> s.replaceAll("^\"|\"$", "").replaceAll("^'|'$", ""))
                .filter(s -> !s.isEmpty())
                .toArray(String[]::new);
        log.info("Public routes: {}", (Object) publicRoutes);

        return http
                .csrf(ServerHttpSecurity.CsrfSpec::disable)
                .cors(cors -> cors.configurationSource(corsConfigurationSource()))
                .httpBasic(ServerHttpSecurity.HttpBasicSpec::disable)
                .formLogin(ServerHttpSecurity.FormLoginSpec::disable)
                .securityContextRepository(NoOpServerSecurityContextRepository.getInstance())
                .authorizeExchange(exchanges -> exchanges
                        .pathMatchers(publicRoutes).permitAll()
                        .anyExchange().authenticated()
                )
                .addFilterAt(jwtWebFilter, SecurityWebFiltersOrder.AUTHENTICATION)
                .build();
    }
}
