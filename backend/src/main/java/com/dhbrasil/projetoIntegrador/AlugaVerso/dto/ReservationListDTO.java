package com.dhbrasil.projetoIntegrador.AlugaVerso.dto;

import com.dhbrasil.projetoIntegrador.AlugaVerso.model.Reservation;

import java.util.Date;

public class ReservationListDTO {

    private Integer id;

    private Date dateInitial;

    private Date dateFinal;


    public ReservationListDTO() {
    }

    public ReservationListDTO(Reservation reservation) {
        id = reservation.getId();
        dateInitial = reservation.getDateInitial();
        dateFinal = reservation.getDateFinal();

    }

    public Reservation toEntity() {
        Reservation reservation = new Reservation();
        reservation.setId(this.id);
        reservation.setDateInitial(this.dateInitial);
        reservation.setDateFinal(this.dateFinal);

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

}
