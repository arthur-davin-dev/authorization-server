package kh.eco.istad.authorizationserver.security;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Set;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.stereotype.Component;

@Component
public class JwtRolesAuthenticationConverter implements Converter<Jwt, Collection<GrantedAuthority>> {
    private static final Set<String> APPLICATION_ROLES = Set.of("ROLE_USER", "ROLE_ADMIN");
    private final JwtGrantedAuthoritiesConverter scopes = new JwtGrantedAuthoritiesConverter();

    @Override
    public Collection<GrantedAuthority> convert(Jwt jwt) {
        Collection<GrantedAuthority> authorities = new ArrayList<>();
        Collection<GrantedAuthority> scopeAuthorities = scopes.convert(jwt);
        if (scopeAuthorities != null) {
            authorities.addAll(scopeAuthorities);
        }
        List<String> roles = jwt.getClaimAsStringList("roles");
        if (roles != null) {
            roles.stream().filter(APPLICATION_ROLES::contains)
                    .map(SimpleGrantedAuthority::new).forEach(authorities::add);
        }
        return authorities;
    }
}
