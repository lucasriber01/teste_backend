package com.dhbrasil.projetoIntegrador.AlugaVerso.dto;

import com.dhbrasil.projetoIntegrador.AlugaVerso.model.Role;

import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

public class RoleDTO {

    private Integer id;
    private String name;

    public static List<RoleDTO> fromEntity(Collection<Role> roles) {
        return roles.stream()
                .map(r -> new RoleDTO(r))
                .collect(Collectors.toList());
    }

    public RoleDTO(){}

    public RoleDTO(Integer id, String name) {
        this.id = id;
        this.name = name;
    }

    public RoleDTO(Role role){
        id = role.getId();
        name = role.getName();
    }

    public Role toEntity(){
        return new Role(this.id, this.name);
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
}
