package com.winnguyen1905.gateway.config;

import java.util.Arrays;

import org.springframework.boot.autoconfigure.web.WebProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.context.NoOpServerSecurityContextRepository;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;

@Configuration
@EnableWebFluxSecurity
public class SecurityConfig {

  private final String[] whiteList = { 
    "/**",
    "/auth/register",
    "/api/auth/**", "/api/v1/auth/login", "/api/v1/auth/refresh",
    "/storage/**", "/api/v1/products/**" };

  @Bean
  WebProperties.Resources resources() {
    return new WebProperties.Resources();
  }

  @Bean
  PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder();
  }

  @Bean
  SecurityWebFilterChain springWebFilterChain(ServerHttpSecurity http,
      CustomServerAuthenticationEntryPoint serverAuthenticationEntryPoint,
      ReactiveAuthenticationManager reactiveAuthenticationManager) {

    return http.csrf(ServerHttpSecurity.CsrfSpec::disable).httpBasic(ServerHttpSecurity.HttpBasicSpec::disable)
        .authenticationManager(reactiveAuthenticationManager)
        .securityContextRepository(NoOpServerSecurityContextRepository.getInstance())
        .authorizeExchange(authorizeExchangeSpec -> authorizeExchangeSpec.pathMatchers(this.whiteList).permitAll()
            .pathMatchers("/ws/events").permitAll()
            .pathMatchers("/auth/**", "/stripe/**", "/swagger-ui/**", "/api-docs/**", "/webjars/**").permitAll()
            .pathMatchers("/admin/**").hasAnyAuthority("ADMIN", "ROLE_ADMIN").anyExchange().authenticated()
        // .addFilterBefore(webFilter, SecurityWebFiltersOrder.HTTP_BASIC)
        )
        .oauth2ResourceServer(
            (oauth2) -> oauth2.jwt(Customizer.withDefaults()).authenticationEntryPoint(serverAuthenticationEntryPoint))
        .build();
  }

  @Bean
  UrlBasedCorsConfigurationSource corsConfigurationSource() {
    CorsConfiguration configuration = new CorsConfiguration();
    configuration
        .setAllowedOrigins(Arrays.asList("https://locolhost:3000", "https://locolhost:4173", "*"));
    configuration.setAllowedMethods(Arrays.asList("GET", "POST", "DELETE", "PUT", "PATCH", "OPTIONS"));
    configuration.setAllowCredentials(true);
    configuration.addAllowedHeader("*");
    configuration
        .setAllowedHeaders(Arrays.asList("Content-Type", "Authorization", "Accept", "x-no-retry", "x-api-key"));
    configuration.setMaxAge(3600L);
    UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
    source.registerCorsConfiguration("/**", configuration);
    return source;
  }
}
