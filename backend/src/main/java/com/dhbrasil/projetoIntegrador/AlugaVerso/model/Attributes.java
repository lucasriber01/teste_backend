package com.dhbrasil.projetoIntegrador.AlugaVerso.model;

import org.hibernate.annotations.SQLDelete;
import org.hibernate.annotations.Where;

import javax.persistence.*;
import java.time.Instant;

@Entity
@Table(name = "attributes")
@SQLDelete(sql = "UPDATE attributes SET deleted=true, deleted_at=now() WHERE id=?")
@Where(clause = "deleted=false")
public class Attributes {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Integer id;
    private String name;
    private String icon;
    @Column(columnDefinition = "TIMESTAMP WITHOUT TIME ZONE")
    private Instant createdAt;

    @Column(columnDefinition = "TIMESTAMP WITHOUT TIME ZONE")
    private Instant updatedAt;

    @Column(name = "deleted")
    private boolean deleted = Boolean.FALSE;

    @Column(columnDefinition = "TIMESTAMP WITHOUT TIME ZONE")
    private Instant deletedAt;

    public Attributes(){}

    public Attributes(Integer id, String name, String icon) {
        this.id = id;
        this.name = name;
        this.icon = icon;
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

    @PrePersist
    public void prePersist(){

        createdAt = Instant.now();
        deleted = false;
    }

    @PreUpdate
    public void preUpdate(){
        updatedAt = Instant.now();
    }
}
