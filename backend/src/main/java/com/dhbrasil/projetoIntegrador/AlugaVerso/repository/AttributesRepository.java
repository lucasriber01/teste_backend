package com.dhbrasil.projetoIntegrador.AlugaVerso.repository;

import com.dhbrasil.projetoIntegrador.AlugaVerso.model.Attributes;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface AttributesRepository extends JpaRepository<Attributes, Integer> {
}
