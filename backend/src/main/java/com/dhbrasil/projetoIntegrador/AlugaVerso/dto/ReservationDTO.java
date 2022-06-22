package com.dhbrasil.projetoIntegrador.AlugaVerso.dto;

import com.dhbrasil.projetoIntegrador.AlugaVerso.model.Reservation;

import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotNull;
import java.time.Instant;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.Date;

public class ReservationDTO {

    private Integer id;

    private Date dateInitial;

    private Date dateFinal;
    private UserDTO user;
    private LandResponseDTO land;

    public ReservationDTO(){}

    public ReservationDTO(Reservation reservation){
        id = reservation.getId();
        dateInitial = reservation.getDateInitial();
        dateFinal = reservation.getDateFinal();
        user = new UserDTO(reservation.getUser());
        land = new LandResponseDTO(reservation.getLand());// este campo estava comentado por algum motivo
    }

    public Reservation toEntity(){
        Reservation reservation = new Reservation();
        reservation.setId(this.id);
        reservation.setDateInitial(this.dateInitial);
        reservation.setDateFinal(this.dateFinal);
        reservation.setUser(this.user.toEntity());
        reservation.setLand(this.land.toEntity());
        return reservation;
    }

    public Integer getId() {
        return id;
    }

    public void setId(Integer id) {
        this.id = id;
    }

    public Date getDateInitial() {
        return dateInitial;
    }

    public void setDateInitial(Date dateInitial) {
        this.dateInitial = dateInitial;
    }

    public Date getDateFinal() {
        return dateFinal;
    }

    public void setDateFinal(Date dateFinal) {
        this.dateFinal = dateFinal;
    }

    public UserDTO getUser() {
        return user;
    }

    public void setUser(UserDTO user) {
        this.user = user;
    }

    public LandResponseDTO getLand() {
        return land;
    }

    public void setLand(LandResponseDTO land) {
        this.land = land;
    }
}
