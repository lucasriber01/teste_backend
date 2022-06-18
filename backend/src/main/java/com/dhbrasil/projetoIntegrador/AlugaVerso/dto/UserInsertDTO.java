package com.dhbrasil.projetoIntegrador.AlugaVerso.dto;

import com.dhbrasil.projetoIntegrador.AlugaVerso.model.User;
import com.dhbrasil.projetoIntegrador.AlugaVerso.service.validation.UserInsertValid;

@UserInsertValid
public class UserInsertDTO extends UserDTO{
    private String password;

    UserInsertDTO() {
        super();
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }


}
