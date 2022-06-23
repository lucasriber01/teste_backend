package com.dhbrasil.projetoIntegrador.AlugaVerso.security;

import com.dhbrasil.projetoIntegrador.AlugaVerso.dto.RoleDTO;
import com.dhbrasil.projetoIntegrador.AlugaVerso.dto.UserDTO;
import com.dhbrasil.projetoIntegrador.AlugaVerso.model.Role;
import io.jsonwebtoken.*;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

public class JWTCreator {
    public static final String HEADER_AUTHORIZATION = "Authorization";
    public static final String ROLES_AUTHORITIES = "authorities";
    public static final String USER = "user";

    public static String create(String prefix, String key, JWTObject jwtObject) {
        String token = Jwts.builder()
                .setSubject(jwtObject.getSubject())
                .setIssuedAt(jwtObject.getIssuedAt())
                .setExpiration(jwtObject.getExpiration())
                .claim(ROLES_AUTHORITIES, jwtObject.getRoles())
                .claim(USER, jwtObject.getUser())
                .signWith(SignatureAlgorithm.HS512, key).compact();
        return prefix + " " + token;
    }

    public static JWTObject create(String token, String prefix, String key)
            throws ExpiredJwtException, UnsupportedJwtException, MalformedJwtException, SignatureException {
        JWTObject object = new JWTObject();
        token = token.replace(prefix, "");
        Claims claims = Jwts.parser().setSigningKey(key).parseClaimsJws(token).getBody();
        object.setSubject(claims.getSubject());
        object.setExpiration(claims.getExpiration());
        object.setIssuedAt(claims.getIssuedAt());
        object.setRoles((List) claims.get(ROLES_AUTHORITIES));
        object.setUser(mapToUser(claims.get(USER, Map.class)));
        return object;

    }

    private static UserDTO mapToUser(Map props) {
        if (props == null) {
            return null;
        }

        UserDTO u = new UserDTO();
        u.setId((Integer) props.get("id"));
        u.setEmail((String) props.get("email"));
        u.setName((String) props.get("name"));
        u.setLastName((String) props.get("lastName"));
        return u;
    }

    private static List<RoleDTO> roleToRoleDTO(List<Role> roles) {
        return roles.stream()
                .map(role -> new RoleDTO(role))
                .collect(Collectors.toList());
    }
}
