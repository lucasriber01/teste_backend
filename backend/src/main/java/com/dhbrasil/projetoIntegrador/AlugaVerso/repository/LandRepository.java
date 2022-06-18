package com.dhbrasil.projetoIntegrador.AlugaVerso.repository;

import com.dhbrasil.projetoIntegrador.AlugaVerso.model.Land;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.Date;
import java.util.List;
@Repository
public interface LandRepository extends JpaRepository<Land, Integer> {
    List<Land> findByCategoryId(Integer id);
    List<Land> findByMetaverseId(Integer id);

    @Query("SELECT l FROM Land l " +
            "join l.reservation r " +
            "WHERE l.metaverse.name = :metaverseName and not (r.dateInitial >= :initialDate and r.dateFinal <= :endDate)")
    List<Land> findByMetaverseAndReservationDates(@Param("metaverseName") String metaverseName,
                                                  @Param("initialDate") Date initialDate,
                                                  @Param("endDate") Date endDate);
}
