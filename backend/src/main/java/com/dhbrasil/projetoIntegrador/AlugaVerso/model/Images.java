package com.dhbrasil.projetoIntegrador.AlugaVerso.model;

import org.hibernate.annotations.SQLDelete;
import org.hibernate.annotations.Where;

import javax.persistence.*;
import java.time.Instant;
import java.util.Objects;

@Entity
@Table(name = "images")
@SQLDelete(sql = "UPDATE images SET deleted=true, deleted_at=now() WHERE id=?")
@Where(clause = "deleted=false")
public class Images {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Integer id;
    private String title;
    private String url;

    @Column(columnDefinition = "TIMESTAMP WITHOUT TIME ZONE")
    private Instant createdAt;

    @Column(columnDefinition = "TIMESTAMP WITHOUT TIME ZONE")
    private Instant updatedAt;

    @Column(name = "deleted")
    private boolean deleted = Boolean.FALSE;

    @Column(columnDefinition = "TIMESTAMP WITHOUT TIME ZONE")
    private Instant deletedAt;

    @ManyToOne()
    @JoinColumn(name = "land_id")
    private Land land;

    public Images() {
    }

    public Images(Integer id, String title, String url) {
        this.id = id;
        this.title = title;
        this.url = url;
    }

    public Images(String title, String url, Land land) {
        this.title = title;
        this.url = url;
        this.land = land;
    }

    public Images(String title, String url) {
        this.title = title;
        this.url = url;
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

    public Land getLand() {
        return land;
    }

    public void setLand(Land land) {
        this.land = land;
    }

    @PrePersist
    public void prePersist() {
        createdAt = Instant.now();
        deleted = false;
    }

    @PreUpdate
    public void preUpdate() {
        updatedAt = Instant.now();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Images images = (Images) o;
        return deleted == images.deleted && Objects.equals(id, images.id) && Objects.equals(title, images.title) && Objects.equals(url, images.url) && Objects.equals(createdAt, images.createdAt) && Objects.equals(updatedAt, images.updatedAt) && Objects.equals(deletedAt, images.deletedAt);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id, title, url, createdAt, updatedAt, deleted, deletedAt);
    }

    @Override
    public String toString() {
        return "Images{" +
                "id=" + id +
                ", title='" + title + '\'' +
                ", url='" + url + '\'' +
                ", createdAt=" + createdAt +
                ", updatedAt=" + updatedAt +
                ", deleted=" + deleted +
                ", deletedAt=" + deletedAt +
                '}';
    }
}
