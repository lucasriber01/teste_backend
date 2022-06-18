package com.dhbrasil.projetoIntegrador.AlugaVerso.repository;

import com.dhbrasil.projetoIntegrador.AlugaVerso.model.Metaverse;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface MetaverseRepository extends JpaRepository<Metaverse, Integer> {
}
