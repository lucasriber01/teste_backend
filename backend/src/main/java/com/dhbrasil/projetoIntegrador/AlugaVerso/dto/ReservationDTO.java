package com.dhbrasil.projetoIntegrador.AlugaVerso.dto;

import com.dhbrasil.projetoIntegrador.AlugaVerso.model.Reservation;

import java.time.Instant;
import java.util.Date;

public class ReservationDTO {

    private Integer id;
    private Instant startTime;
    private Date dateInitial;
    private Date dateFinal;
    private UserDTO user;
    private LandDTO land;

    public ReservationDTO(){}

    public ReservationDTO(Reservation reservation){
        id = reservation.getId();
        startTime = reservation.getStartTime();
        dateInitial = reservation.getDateInitial();
        dateFinal = reservation.getDateFinal();
        user = new UserDTO(reservation.getUser());
        //land = new LandDTO(reservation.getLand());
    }

    public Reservation toEntity(){
        Reservation reservation = new Reservation();
        reservation.setId(this.id);
        reservation.setStartTime(this.startTime);
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

    public Instant getStartTime() {
        return startTime;
    }

    public void setStartTime(Instant startTime) {
        this.startTime = startTime;
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

    public LandDTO getLand() {
        return land;
    }

    public void setLand(LandDTO land) {
        this.land = land;
    }
}
