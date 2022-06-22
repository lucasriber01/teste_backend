package com.dhbrasil.projetoIntegrador.AlugaVerso.dto;

import com.dhbrasil.projetoIntegrador.AlugaVerso.model.Category;
import java.util.ArrayList;
import java.util.List;

public class CategoryDTO {

    private Integer id;
    private String name;
    private String imagemUrl;
    private String description;

    private List<LandDTO> land = new ArrayList<>();

    public CategoryDTO(){}

    public CategoryDTO(Integer id, String name, String imagemUrl, String description) {
        this.id = id;
        this.name = name;
        this.imagemUrl = imagemUrl;
        this.description = description;
    }

    public Category toEntity(){
        Category category = new Category();
        category.setId(this.id);
        category.setName(this.name);
        category.setImagemUrl(this.imagemUrl);
        category.setDescription(this.description);
        this.land.forEach(l ->category.getLand().add(l.toEntity()));
        return category;
    }

    public CategoryDTO(Category category){
        this.id = category.getId();
        this.name = category.getName();
        this.imagemUrl = category.getImagemUrl();
        this.description = category.getDescription();
        //category.getLand().forEach(l-> this.land.add(new LandDTO(l)));
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

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public List<LandDTO> getLand() {
        return land;
    }

    public void setLand(List<LandDTO> land) {
        this.land = land;
    }
}
