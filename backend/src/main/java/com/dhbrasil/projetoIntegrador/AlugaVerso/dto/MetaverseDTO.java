package com.dhbrasil.projetoIntegrador.AlugaVerso.dto;

import com.dhbrasil.projetoIntegrador.AlugaVerso.model.Metaverse;

public class MetaverseDTO {

    private Integer id;
    private String name;

    private String imagemUrl;

    public MetaverseDTO(){}

    public MetaverseDTO(Integer id, String name, String imagemUrl) {
        this.id = id;
        this.name = name;
        this.imagemUrl = imagemUrl;
    }

    public Metaverse toEntity(){

        return new Metaverse(this.id, this.name, this.imagemUrl);
    }

    public MetaverseDTO(Metaverse metaverse){
        this.id = metaverse.getId();
        this.name = metaverse.getName();
        this.imagemUrl = metaverse.getImagemUrl();
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

    public String getImagemUrl() {
        return imagemUrl;
    }

    public void setImagemUrl(String imagemUrl) {
        this.imagemUrl = imagemUrl;
    }
}
