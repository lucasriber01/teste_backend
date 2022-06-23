package com.dhbrasil.projetoIntegrador.AlugaVerso.security;

import com.dhbrasil.projetoIntegrador.AlugaVerso.dto.UserDTO;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

public class JWTObject {

    private String subject;
    private Date issuedAt;
    private Date expiration;
    private List<String> roles = new ArrayList<>();
    private UserDTO user;



    public String getSubject() {
        return subject;
    }

    public void setSubject(String subject) {
        this.subject = subject;
    }

    public Date getIssuedAt() {
        return issuedAt;
    }

    public void setIssuedAt(Date issuedAt) {
        this.issuedAt = issuedAt;
    }

    public Date getExpiration() {
        return expiration;
    }

    public void setExpiration(Date expiration) {
        this.expiration = expiration;
    }

//    public List<String> getRoles() {
//        return roles;
//    }
//
//    public void setRoles(List<String> roles) {
//        this.roles = roles;
//    }


    public List<String> getRoles() {
        return roles;
    }

    public void setRoles(List<String> roles) {
        this.roles = roles;
    }

    public UserDTO getUser() {
        return user;
    }

    public void setUser(UserDTO user) {
        this.user = user;
    }
}
