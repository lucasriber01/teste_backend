package com.dhbrasil.projetoIntegrador.AlugaVerso.service.validation;

import com.dhbrasil.projetoIntegrador.AlugaVerso.controller.exceptions.FieldMessage;
import com.dhbrasil.projetoIntegrador.AlugaVerso.dto.UserInsertDTO;
import com.dhbrasil.projetoIntegrador.AlugaVerso.model.User;
import com.dhbrasil.projetoIntegrador.AlugaVerso.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;

import javax.validation.ConstraintValidator;
import javax.validation.ConstraintValidatorContext;
import java.util.ArrayList;
import java.util.List;

public class UserInsertValidator implements ConstraintValidator<UserInsertValid, UserInsertDTO> {

    @Autowired
    private UserRepository userRepository;
    @Override
    public void initialize(UserInsertValid ann) {
    }

    @Override
    public boolean isValid(UserInsertDTO dto, ConstraintValidatorContext context) {

        List<FieldMessage> list = new ArrayList<>();

        User user = userRepository.findByEmail(dto.getEmail());
        if(user != null){
            list.add(new FieldMessage("email", "Email já existe"));
        }

        for (FieldMessage e : list) {
            context.disableDefaultConstraintViolation();
            context.buildConstraintViolationWithTemplate(e.getMessage()).addPropertyNode(e.getFieldName())
                    .addConstraintViolation();
        }
        return list.isEmpty();
    }
}
