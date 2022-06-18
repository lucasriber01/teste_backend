package com.dhbrasil.projetoIntegrador.AlugaVerso.controller;

import com.dhbrasil.projetoIntegrador.AlugaVerso.dto.UserDTO;
import com.dhbrasil.projetoIntegrador.AlugaVerso.dto.UserInsertDTO;
import com.dhbrasil.projetoIntegrador.AlugaVerso.dto.UserUpdateDTO;
import com.dhbrasil.projetoIntegrador.AlugaVerso.repository.UserRepository;
import com.dhbrasil.projetoIntegrador.AlugaVerso.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import javax.validation.Valid;
import java.net.URI;
import java.util.List;

@RestController
@RequestMapping("/users")
public class UserController {


    @Autowired
    private UserService userService;
    @Autowired
    private UserRepository userRepository;

    //Cadastrar usuário
    @PostMapping
    public ResponseEntity<UserDTO> createdUser(@RequestBody @Valid UserInsertDTO userInsertDTO){
        //Integer id = userService.insert(dto);
        //UserDTO userDTO = new UserDTO(userRepository.findById(id).get());
        UserDTO newDto = userService.insert(userInsertDTO);
        URI uri = ServletUriComponentsBuilder.fromCurrentRequest().path("/{id}")
                .buildAndExpand(newDto.getId()).toUri();
        return ResponseEntity.created(uri).body(newDto);

//        URI uri = ServletUriComponentsBuilder.fromCurrentRequest().path("/{id}")
//                .buildAndExpand(dto.getId()).toUri();
//        return ResponseEntity.created(uri).body(userDTO);
    }

    //Listar todas os usuários
    @GetMapping
   public ResponseEntity<List<UserDTO>> listUser(){
       List<UserDTO> list = userService.findAll();
       return ResponseEntity.ok().body(list);
   }

    //Busca por id
    @GetMapping(value = "/{id}")
    public ResponseEntity<UserDTO> findById(@PathVariable Integer id){
        UserDTO userDTO = userService.findById(id);
        return ResponseEntity.ok().body(userDTO);
    }

    //Atualizar user
    @PutMapping(value = "/{id}")
    public ResponseEntity<UserDTO> updateUser(@PathVariable Integer id, @Valid @RequestBody UserUpdateDTO dto){
        UserDTO newDto = userService.update(id, dto);
        return ResponseEntity.ok().body(newDto);
    }

    //Deletar user
    @DeleteMapping(value = "/{id}")
    public ResponseEntity<UserDTO> delete(@PathVariable Integer id){
        userService.delete(id);
        return ResponseEntity.noContent().build();
    }
   public ResponseEntity<List<UserDTO>> listLand(){
       List<UserDTO> list = userService.findAll();
       return ResponseEntity.ok().body(list);
   }
}