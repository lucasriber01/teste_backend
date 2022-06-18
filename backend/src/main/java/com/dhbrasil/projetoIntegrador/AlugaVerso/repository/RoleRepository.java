package com.dhbrasil.projetoIntegrador.AlugaVerso.repository;

import com.dhbrasil.projetoIntegrador.AlugaVerso.model.Role;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface RoleRepository extends JpaRepository<Role, Integer> {
}
