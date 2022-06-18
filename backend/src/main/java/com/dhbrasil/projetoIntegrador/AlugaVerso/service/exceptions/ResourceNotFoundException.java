package com.dhbrasil.projetoIntegrador.AlugaVerso.service.exceptions;

public class ResourceNotFoundException extends RuntimeException{
    public ResourceNotFoundException(String msg) {
        super(msg);
    }
}
