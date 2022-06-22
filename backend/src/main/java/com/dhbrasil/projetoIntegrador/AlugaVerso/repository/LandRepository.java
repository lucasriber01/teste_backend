package com.dhbrasil.projetoIntegrador.AlugaVerso.repository;

import com.dhbrasil.projetoIntegrador.AlugaVerso.model.Land;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.Date;
import java.util.List;
@Repository
public interface LandRepository extends JpaRepository<Land, Integer> {
    List<Land> findByCategoryId(Integer id);
    List<Land> findByMetaverseId(Integer id);

    @Query("SELECT l FROM Land l " +
            "WHERE l.metaverse.name = :metaverseName AND NOT EXISTS (" +
            "   SELECT r.id FROM Reservation r " +
            "   WHERE r.land.id = l.id and ( " +
            "       (:initialDate >= r.dateInitial AND :initialDate <= r.dateFinal) OR " +
            "       (:endDate >= r.dateInitial AND :endDate <= r.dateFinal)" +
            "   ) " +
            ")")
    List<Land> findByMetaverseAndReservationDates(@Param("metaverseName") String metaverseName,
                                                  @Param("initialDate") Date initialDate,
                                                  @Param("endDate") Date endDate);


    /*
    * RESERVA
    * 5 10
    * BUSCA 1
    * r.dateInitial >= :initialDate OR r.dateFinal <= :endDate
    * 5 8
    * */

}
