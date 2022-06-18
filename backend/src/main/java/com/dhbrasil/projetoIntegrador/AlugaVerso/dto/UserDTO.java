package com.dhbrasil.projetoIntegrador.AlugaVerso.dto;


import com.dhbrasil.projetoIntegrador.AlugaVerso.model.User;

import javax.validation.constraints.Email;
import javax.validation.constraints.NotBlank;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class UserDTO {

    private Integer id;
    @NotBlank(message = "Campo obrigatório")
    private String name;
    private String lastName;
    @Email(message = "Favor entrar um email válido")
    private String email;
    List<RoleDTO> roles = new ArrayList<>();

    public UserDTO(){}

    public UserDTO(Integer id, String name, String lastName, String email) {
        this.id = id;
        this.name = name;
        this.lastName = lastName;
        this.email = email;
    }

    public UserDTO(User user){
        id = user.getId();
        name = user.getName();
        lastName = user.getLastName();
        email = user.getEmail();
        user.getRoles().forEach(role -> this.roles.add(new RoleDTO(role)));
    }

    public User toEntity(){
        User user = new User();
        user.setId(this.id);
        user.setName(this.name);
        user.setLastName(this.lastName);
        user.setEmail(this.email);
        this.roles.forEach(role -> user.getRoles().add(role.toEntity()));
        return user;
    }

    public Integer getId() {
        return id;
    }

    public void setId(Integer id) {
        this.id = id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getLastName() {
        return lastName;
    }

    public void setLastName(String lastName) {
        this.lastName = lastName;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public List<RoleDTO> getRoles() {
        return roles;
    }
}
