package com.dhbrasil.projetoIntegrador.AlugaVerso.repository;

import com.dhbrasil.projetoIntegrador.AlugaVerso.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface UserRepository extends JpaRepository<User, Integer> {
    User findByEmail(String email);
}
