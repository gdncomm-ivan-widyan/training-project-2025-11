package com.example.gateway.config;

import com.example.common.security.JwtService;
import com.example.gateway.properties.GatewaySecurityProperties;
import com.example.gateway.properties.JwtProperties;
import com.example.gateway.security.JwtAuthFilter;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

  private final GatewaySecurityProperties securityProps;
  private final JwtProperties jwtProps;

  @Bean
  public JwtService jwtService() {
    // Secret now comes from properties
    return new JwtService(jwtProps.getSecret());
  }

  @Bean
  public SecurityFilterChain filterChain(HttpSecurity http, JwtService jwtService) throws Exception {
    http.csrf(AbstractHttpConfigurer::disable)
        .authorizeHttpRequests(auth -> {

          // Public paths
          if (securityProps.getPublicPaths() != null) {
            securityProps.getPublicPaths()
                .forEach(path -> auth.requestMatchers(path).permitAll());
          }

          // Authenticated paths
          if (securityProps.getAuthenticatedPaths() != null) {
            securityProps.getAuthenticatedPaths()
                .forEach(path -> auth.requestMatchers(path).authenticated());
          }

          // Everything else (for now)
          auth.anyRequest().permitAll();
        })
        .addFilterBefore(
            new JwtAuthFilter(jwtService, securityProps),
            UsernamePasswordAuthenticationFilter.class
        )
        .httpBasic(Customizer.withDefaults());

    return http.build();
  }
}