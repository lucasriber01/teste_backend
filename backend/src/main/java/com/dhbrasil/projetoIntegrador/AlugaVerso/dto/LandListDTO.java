package com.dhbrasil.projetoIntegrador.AlugaVerso.dto;

import com.dhbrasil.projetoIntegrador.AlugaVerso.model.Land;

import javax.validation.constraints.Positive;
import java.util.ArrayList;
import java.util.List;

public class LandListDTO {

    private Integer id;
    private String name;
    private String description;
    private String localizationX;
    private String localizationY;
    @Positive(message = "Preço deve ser um valor positivo")
    private Double price;

    private List<ImagesDTO> images = new ArrayList<>();
    private List<AttributesDTO> attributes = new ArrayList<>();
    private CategoryDTO category;
    private MetaverseDTO metaverse;
    private List<ReservationListDTO> reservation = new ArrayList<>();


    public LandListDTO() {
    }

    public LandListDTO(Integer id, String name, String description, String localizationX, String localizationY) {
        this.id = id;
        this.name = name;
        this.description = description;
        this.localizationX = localizationX;
        this.localizationY = localizationY;

    }

    public Land toEntity() {

        Land land = new Land();
        land.setId(this.id);
        land.setName(this.name);
        land.setDescription(this.description);
        land.setLocalizationX(this.localizationX);
        land.setLocalizationY(this.localizationY);
        land.setPrice(this.price);
        this.images.forEach(img -> land.getImages().add(img.toEntity()));
        this.attributes.forEach(attr -> land.getAttributes().add(attr.toEntity()));
        this.reservation.forEach(res -> land.getReservation().add(res.toEntity()));
        if (this.category != null) land.setCategory(this.category.toEntity());
        if (this.metaverse != null) land.setMetaverse(this.metaverse.toEntity());
        return land;
    }

    public LandListDTO(Land land) {
        this.id = land.getId();
        this.name = land.getName();
        this.description = land.getDescription();
        this.localizationX = land.getLocalizationX();
        this.localizationY = land.getLocalizationY();
        this.price = land.getPrice();
        this.category = new CategoryDTO(land.getCategory());
        this.metaverse = new MetaverseDTO(land.getMetaverse());
        land.getImages().forEach(image -> this.images.add(new ImagesDTO(image)));
        land.getAttributes().forEach(attr -> this.attributes.add(new AttributesDTO(attr)));
        land.getReservation().forEach(res -> this.reservation.add(new ReservationListDTO(res)));
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

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public String getLocalizationX() {
        return localizationX;
    }

    public void setLocalizationX(String localizationX) {
        this.localizationX = localizationX;
    }

    public String getLocalizationY() {
        return localizationY;
    }

    public void setLocalizationY(String localizationY) {
        this.localizationY = localizationY;
    }

    public List<ImagesDTO> getImages() {
        return images;
    }

    public void setImages(List<ImagesDTO> images) {
        this.images = images;
    }

    public List<AttributesDTO> getAttributes() {
        return attributes;
    }

    public void setAttributes(List<AttributesDTO> attributes) {
        this.attributes = attributes;
    }

    public Double getPrice() {
        return price;
    }

    public void setPrice(Double price) {
        this.price = price;
    }

    public CategoryDTO getCategory() {
        return category;
    }

    public void setCategory(CategoryDTO category) {
        this.category = category;
    }

    public MetaverseDTO getMetaverse() {
        return metaverse;
    }

    public void setMetaverse(MetaverseDTO metaverse) {
        this.metaverse = metaverse;
    }

    public List<ReservationListDTO> getReservation() {
        return reservation;
    }

    public void setReservation(List<ReservationListDTO> reservation) {
        this.reservation = reservation;
    }
}
