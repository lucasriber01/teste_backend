package com.dhbrasil.projetoIntegrador.AlugaVerso.service;

import com.dhbrasil.projetoIntegrador.AlugaVerso.dto.LoginDTO;
import com.dhbrasil.projetoIntegrador.AlugaVerso.dto.SessionDTO;
import com.dhbrasil.projetoIntegrador.AlugaVerso.dto.UserDTO;
import com.dhbrasil.projetoIntegrador.AlugaVerso.model.Role;
import com.dhbrasil.projetoIntegrador.AlugaVerso.model.User;
import com.dhbrasil.projetoIntegrador.AlugaVerso.repository.UserRepository;
import com.dhbrasil.projetoIntegrador.AlugaVerso.security.JWTCreator;
import com.dhbrasil.projetoIntegrador.AlugaVerso.security.JWTObject;
import com.dhbrasil.projetoIntegrador.AlugaVerso.security.SecurityConfig;
import com.dhbrasil.projetoIntegrador.AlugaVerso.service.exceptions.LoginException;
import com.dhbrasil.projetoIntegrador.AlugaVerso.service.exceptions.ResourceNotFoundException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Date;
import java.util.stream.Collectors;

@Service
public class LoginService {

    @Autowired
    private PasswordEncoder encoder;
    @Autowired
    private SecurityConfig securityConfig;
    @Autowired
    private UserRepository repository;

    public SessionDTO login(LoginDTO login) {
        User user = repository.findByEmail(login.getEmail());
        if(user!=null) {
            boolean passwordOk =  encoder.matches(login.getPassword(), user.getPassword());
            if (!passwordOk) {
                throw new LoginException("Senha inválida, tente novamente!");
            }
            //Objeto SessionDTO enviado para obter o retorno das informações de login do usuário
            SessionDTO session = new SessionDTO();
            session.setLogin(user.getName() + " " + user.getLastName());
            // Token JWT gerado e inserido na sessão
            JWTObject jwtObject = new JWTObject();
            jwtObject.setIssuedAt(new Date(System.currentTimeMillis()));
            jwtObject.setExpiration((new Date(System.currentTimeMillis() + SecurityConfig.EXPIRATION)));
            jwtObject.setRoles(user.getRoles().stream().map(Role::getName).collect(Collectors.toList()));
            jwtObject.setUser(new UserDTO(user));
            session.setToken(JWTCreator.create(SecurityConfig.PREFIX, SecurityConfig.KEY, jwtObject));
            return session;
        }else {
            throw new ResourceNotFoundException("Email não cadastrado!");
        }
    }
}
