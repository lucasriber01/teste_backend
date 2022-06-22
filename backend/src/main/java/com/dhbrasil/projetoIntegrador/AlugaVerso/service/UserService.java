package com.dhbrasil.projetoIntegrador.AlugaVerso.service;

import com.dhbrasil.projetoIntegrador.AlugaVerso.dto.RoleDTO;
import com.dhbrasil.projetoIntegrador.AlugaVerso.dto.UserDTO;
import com.dhbrasil.projetoIntegrador.AlugaVerso.dto.UserInsertDTO;
import com.dhbrasil.projetoIntegrador.AlugaVerso.dto.UserUpdateDTO;
import com.dhbrasil.projetoIntegrador.AlugaVerso.model.Role;
import com.dhbrasil.projetoIntegrador.AlugaVerso.model.User;
import com.dhbrasil.projetoIntegrador.AlugaVerso.repository.RoleRepository;
import com.dhbrasil.projetoIntegrador.AlugaVerso.repository.UserRepository;
import com.dhbrasil.projetoIntegrador.AlugaVerso.service.exceptions.DatabaseException;
import com.dhbrasil.projetoIntegrador.AlugaVerso.service.exceptions.ResourceNotFoundException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import javax.persistence.EntityNotFoundException;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

import static org.springframework.http.HttpStatus.NOT_FOUND;

@Service
public class UserService  implements UserDetailsService {
    private static Logger logger = LoggerFactory.getLogger(UserService.class);
    @Autowired
    private UserRepository userRepository;

    @Autowired
    private RoleRepository roleRepository;

    @Autowired
    private BCryptPasswordEncoder passwordEncoder;

    //Inserir usuário
//    @Transactional
//    public Integer insert(UserDTO userDTO){
//        User user = userRepository.save(userDTO.toEntity());
//        return user.getId();
//    }

    @Transactional
    public UserDTO insert(UserInsertDTO dto) {
        User newUser = new User();
        copyDtoToNewUser(dto, newUser);
        newUser.setPassword(passwordEncoder.encode(dto.getPassword()));
        newUser = userRepository.save(newUser);
        return new UserDTO(newUser);
    }


    //Busca por id
    @Transactional(readOnly = true)
    public UserDTO findById(Integer id){
        Optional<User> userObj = userRepository.findById(id);
        User user = userObj.orElseThrow(()-> new ResponseStatusException(NOT_FOUND));
        return new UserDTO(user);
    }

    //Listar todas os user
    @Transactional(readOnly = true)
    public List<UserDTO> findAll(){
        List<User> list = userRepository.findAll();
        return list.stream().map(x -> new UserDTO(x)).collect(Collectors.toList());
    }

    //Atualizar usuário
    @Transactional
    public UserDTO update(Integer id, UserUpdateDTO dto){
        try {
            User newUser = userRepository.getReferenceById(id);
            copyDtoToNewUser(dto, newUser);
            newUser = userRepository.save(newUser);
            return new UserDTO(newUser);
        }
        catch (EntityNotFoundException e) {
            throw new ResourceNotFoundException("Id not found " + id);
        }
    }

    private void copyDtoToNewUser(UserDTO userDTO, User newUser){
        newUser.setName(userDTO.getName());
        newUser.setLastName(userDTO.getLastName());
        newUser.setEmail(userDTO.getEmail());

        newUser.getRoles().clear();
        for(RoleDTO roleDTO : userDTO.getRoles()){
            Role role = roleRepository.getReferenceById(roleDTO.getId());
            newUser.getRoles().add(role);
        }
    }

    // Deletar usuário
    @Transactional
    public void delete(Integer id){
        try{
            userRepository.deleteById(id);
        } catch (EmptyResultDataAccessException e){
            throw new ResponseStatusException(NOT_FOUND, "Usuário nâo encontrada: "+id);
        }
        catch (DataIntegrityViolationException e) {
            throw new DatabaseException("Integrity violation");
        }
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        User user = userRepository.findByEmail(username);
        if (user == null) {
            logger.error("User not found: " + username);
            throw new UsernameNotFoundException("Email not found");
        }
        logger.info("User found: " + username);
        return user;
    }
}
