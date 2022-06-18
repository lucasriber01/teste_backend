package com.dhbrasil.projetoIntegrador.AlugaVerso.controller;

import com.dhbrasil.projetoIntegrador.AlugaVerso.dto.LoginDTO;
import com.dhbrasil.projetoIntegrador.AlugaVerso.dto.SessionDTO;
import com.dhbrasil.projetoIntegrador.AlugaVerso.service.LoginService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Date;

@RestController
@RequestMapping("/login")
public class LoginController {
    @Autowired
    private LoginService loginService;

    @PostMapping
    public SessionDTO login(@RequestBody LoginDTO login){

        return loginService.login(login);
    }

}
