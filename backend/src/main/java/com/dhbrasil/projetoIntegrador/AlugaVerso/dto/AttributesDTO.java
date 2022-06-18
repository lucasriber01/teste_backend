package com.dhbrasil.projetoIntegrador.AlugaVerso.dto;

import com.dhbrasil.projetoIntegrador.AlugaVerso.model.Attributes;

import javax.persistence.*;


public class AttributesDTO {

    private Integer id;
    private String name;
    private String icon;

    public AttributesDTO(){}

    public AttributesDTO(Integer id, String name, String icon) {
        this.id = id;
        this.name = name;
        this.icon = icon;
    }

    public Attributes toEntity(){
        return new Attributes(this.id, this.name, this.icon);
    }

    public AttributesDTO(Attributes attributes){
        this.id = attributes.getId();
        this.name = attributes.getName();
        this.icon = attributes.getIcon();
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

    public String getIcon() {
        return icon;
    }

    public void setIcon(String icon) {
        this.icon = icon;
    }
}
