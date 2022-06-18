package com.dhbrasil.projetoIntegrador.AlugaVerso.dto;

import com.dhbrasil.projetoIntegrador.AlugaVerso.model.Images;

public class ImagesDTO {

    private Integer id;
    private String title;
    private String url;

    public ImagesDTO(){}

    public ImagesDTO(Integer id, String title, String url) {
        this.id = id;
        this.title = title;
        this.url = url;
    }

    public Images toEntity(){

        return new Images(this.id, this.title, this.url);
    }

    public ImagesDTO(Images images){
        this.id = images.getId();
        this.title = images.getTitle();
        this.url = images.getUrl();
    }

    public Integer getId() {
        return id;
    }

    public void setId(Integer id) {
        this.id = id;
    }

    public String getTitle() {
        return title;
    }

    public void setTitle(String title) {
        this.title = title;
    }

    public String getUrl() {
        return url;
    }

    public void setUrl(String url) {
        this.url = url;
    }

}
