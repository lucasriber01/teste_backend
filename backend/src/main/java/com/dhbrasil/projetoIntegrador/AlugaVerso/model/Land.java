package com.dhbrasil.projetoIntegrador.AlugaVerso.model;

import org.hibernate.annotations.SQLDelete;
import org.hibernate.annotations.Where;

import javax.persistence.*;
import java.time.Instant;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;

@Entity
@Table(name = "land")
@SQLDelete(sql = "UPDATE land SET deleted=true, deleted_at=now() WHERE id=?")
@Where(clause = "deleted=false")
public class Land {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Integer id;
    private String name;
    private String description;
    private String localizationX;
    private String localizationY;

    private Double price;
    @OneToMany(mappedBy = "land", cascade = CascadeType.ALL, fetch = FetchType.EAGER)
    Set<Images> images = new HashSet<>();

    @ManyToOne (fetch = FetchType.EAGER)
    @JoinColumn(name = "category_id")
    private Category category;

    @OneToMany(mappedBy = "land", cascade = CascadeType.ALL, fetch = FetchType.EAGER)
    private Set <Reservation> reservation = new HashSet<>();

    @ManyToOne
    @JoinColumn(name = "metaverse_id")
    private Metaverse metaverse;

    @Column(columnDefinition = "TIMESTAMP WITHOUT TIME ZONE")
    private Instant createdAt;

    @Column(columnDefinition = "TIMESTAMP WITHOUT TIME ZONE")
    private Instant updatedAt;

    @Column(name = "deleted")
    private boolean deleted = Boolean.FALSE;

    @Column(columnDefinition = "TIMESTAMP WITHOUT TIME ZONE")
    private Instant deletedAt;

    @ManyToMany(fetch = FetchType.EAGER)
    @JoinTable(
            name = "tb_land_attributes",
            joinColumns = @JoinColumn(name = "land_id"),
            inverseJoinColumns = @JoinColumn(name = "attributes_id")
    )
    Set<Attributes> attributes = new HashSet<>();

    public Land() {
    }


    public Land(Integer id, String name, String description, String localizationX, String localizationY, Double price) {
        this.id = id;
        this.name = name;
        this.description = description;
        this.localizationX = localizationX;
        this.localizationY = localizationY;
        this.price = price;
    }

    public Land(Integer id, String name, String description, String localizationX, String localizationY, Double price, Set<Images> images, Category category, Metaverse metaverse, Set<Attributes> attributes) {
        this.id = id;
        this.name = name;
        this.description = description;
        this.localizationX = localizationX;
        this.localizationY = localizationY;
        this.price = price;
        this.images = images;
        this.category = category;
        this.metaverse = metaverse;
        this.attributes = attributes;
    }

    public Land(Integer id, String name, String description, String localizationX, String localizationY, Double price, Set<Images> images, Category category, Set<Reservation> reservation, Metaverse metaverse, Set<Attributes> attributes) {
        this.id = id;
        this.name = name;
        this.description = description;
        this.localizationX = localizationX;
        this.localizationY = localizationY;
        this.price = price;
        this.images = images;
        this.category = category;
        this.reservation = reservation;
        this.metaverse = metaverse;
        this.attributes = attributes;
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

    public Set<Images> getImages() {
        return images;
    }

    public Set<Attributes> getAttributes() {
        return attributes;
    }

    public Category getCategory() {
        return category;
    }

    public void setCategory(Category category) {
        this.category = category;
    }

    public Metaverse getMetaverse() {
        return metaverse;
    }

    public void setMetaverse(Metaverse metaverse) {
        this.metaverse = metaverse;
    }

    public Double getPrice() {
        return price;
    }

    public void setPrice(Double price) {
        this.price = price;
    }

    public Set<Reservation> getReservation() {
        return reservation;
    }

    public void setReservation(Set<Reservation> reservation) {
        this.reservation = reservation;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public Instant getUpdatedAt() {
        return updatedAt;
    }

    public Instant getDeletedAt() {
        return deletedAt;
    }

    public void setDeletedAt(Instant deletedAt) {
        this.deletedAt = deletedAt;
    }

    public void setImages(Set<Images> images) {
        this.images = images;
    }

    public void setAttributes(Set<Attributes> attributes) {
        this.attributes = attributes;
    }

    @PrePersist
    public void prePersist() {
        createdAt = Instant.now();
        deleted = false;
        if (images != null) {
            images.forEach(image -> image.setLand(this));
        }
    }

    @PreUpdate
    public void preUpdate() {
        updatedAt = Instant.now();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Land land = (Land) o;
        return deleted == land.deleted && Objects.equals(id, land.id) && Objects.equals(name, land.name) && Objects.equals(description, land.description) && Objects.equals(localizationX, land.localizationX) && Objects.equals(localizationY, land.localizationY) && Objects.equals(price, land.price) && Objects.equals(images, land.images) && Objects.equals(category, land.category) && Objects.equals(metaverse, land.metaverse) && Objects.equals(createdAt, land.createdAt) && Objects.equals(updatedAt, land.updatedAt) && Objects.equals(deletedAt, land.deletedAt) && Objects.equals(attributes, land.attributes);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id, name, description, localizationX, localizationY, price, images, category, metaverse, createdAt, updatedAt, deleted, deletedAt, attributes);
    }

    @Override
    public String toString() {
        return "Land{" +
                "id=" + id +
                ", name='" + name + '\'' +
                ", description='" + description + '\'' +
                ", localizationX='" + localizationX + '\'' +
                ", localizationY='" + localizationY + '\'' +
                ", price=" + price +
                ", images=" + images +
                ", category=" + category +
                ", metaverse=" + metaverse +
                ", createdAt=" + createdAt +
                ", updatedAt=" + updatedAt +
                ", deleted=" + deleted +
                ", deletedAt=" + deletedAt +
                ", attributes=" + attributes +
                ", reservation=" + reservation +
                '}';
    }
}
