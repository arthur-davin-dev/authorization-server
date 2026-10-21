package kh.eco.istad.authorizationserver.config;

import kh.eco.istad.authorizationserver.security.JwtRolesAuthenticationConverter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {
    @Bean
    @Order(2)
    SecurityFilterChain apiFilterChain(
            HttpSecurity http, JwtRolesAuthenticationConverter rolesConverter) throws Exception {
        JwtAuthenticationConverter jwtAuthenticationConverter = new JwtAuthenticationConverter();
        jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(rolesConverter);
        http.securityMatcher("/api/**")
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers("/api/public/**").permitAll()
                        .requestMatchers("/api/admin/**").hasRole("ADMIN")
                        .requestMatchers("/api/scoped/**").hasAuthority("SCOPE_api.read")
                        .anyRequest().authenticated())
                .oauth2ResourceServer(resourceServer -> resourceServer.jwt(jwt ->
                        jwt.jwtAuthenticationConverter(jwtAuthenticationConverter)));
        return http.cors(Customizer.withDefaults()).build();
    }

    @Bean
    @Order(3)
    SecurityFilterChain applicationFilterChain(
            HttpSecurity http, UserDetailsService userDetailsService, PasswordEncoder passwordEncoder)
            throws Exception {
        DaoAuthenticationProvider userAuthenticationProvider = new DaoAuthenticationProvider();
        userAuthenticationProvider.setUserDetailsService(userDetailsService);
        userAuthenticationProvider.setPasswordEncoder(passwordEncoder);
        http.authenticationProvider(userAuthenticationProvider)
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers(
                                "/", "/index.html", "/app.js", "/style.css", "/login.css", "/favicon.ico",
                                "/login", "/error")
                        .permitAll()
                        .anyRequest().authenticated())
                .formLogin(form -> form.loginPage("/login").permitAll());
        return http.cors(Customizer.withDefaults()).build();
    }

    @Bean
    PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
