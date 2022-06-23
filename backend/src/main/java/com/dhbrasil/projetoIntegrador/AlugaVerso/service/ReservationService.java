package com.dhbrasil.projetoIntegrador.AlugaVerso.service;


import com.dhbrasil.projetoIntegrador.AlugaVerso.dto.*;
import com.dhbrasil.projetoIntegrador.AlugaVerso.model.Land;
import com.dhbrasil.projetoIntegrador.AlugaVerso.model.Reservation;
import com.dhbrasil.projetoIntegrador.AlugaVerso.model.User;
import com.dhbrasil.projetoIntegrador.AlugaVerso.repository.*;
import com.dhbrasil.projetoIntegrador.AlugaVerso.service.exceptions.DatabaseException;
import com.dhbrasil.projetoIntegrador.AlugaVerso.service.exceptions.ResourceNotFoundException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

import static org.springframework.http.HttpStatus.FORBIDDEN;
import static org.springframework.http.HttpStatus.NOT_FOUND;

@Service
public class ReservationService {
    @Autowired
    private ReservationRepository reservationRepository;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private LandRepository landRepository;

    //Criar reserva
    @Transactional
    public Integer createReservation(ReservationDTO reservationDTO) {
//
        //Buscar usuário
        UserDTO loggedUser = (UserDTO) SecurityContextHolder.getContext().getAuthentication().getDetails();
        User userEntity = userRepository.findById(loggedUser.getId()).orElseThrow(() -> new ResourceNotFoundException("Usuário não encontrado"));

        //Buscar terrenp
        Optional<Land> landEntity = landRepository.findById(reservationDTO.getLand().getId());
        Land land = landEntity.orElseThrow(() -> new ResourceNotFoundException("Terreno não encontrado"));

        //Efetuar a reserva
        Reservation newReservation = reservationDTO.toEntity();
        newReservation.setUser(userEntity);
        newReservation.setLand(land);

        newReservation = reservationRepository.save(newReservation);

        return newReservation.getId();

    }

    //Lista paginada das reservas
    @Transactional(readOnly = true)
    public Page<ReservationDTO> findAllPaged(PageRequest pageRequest) {
        Page<Reservation> list = reservationRepository.findAll(pageRequest);
        return list.map(x -> new ReservationDTO(x));
    }

    //Listar todas as reservas
    @Transactional(readOnly = true)
    public List<ReservationDTO> findAll() {
        List<Reservation> list = reservationRepository.findAll();
        return list.stream().map(x -> new ReservationDTO(x)).collect(Collectors.toList());
    }

    //Busca por id
    @Transactional(readOnly = true)
    public ReservationDTO findById(Integer id) {
        Optional<Reservation> reservationObj = reservationRepository.findById(id);
        Reservation reservation = reservationObj.orElseThrow(() -> new ResourceNotFoundException("Id não encontrado"));
        return new ReservationDTO(reservation);
    }

    //Deletar reserva
    @Transactional
    public void delete(Integer id) {
        try {
            Reservation reservation = reservationRepository.findById(id)
                    .orElseThrow(() -> new ResponseStatusException(NOT_FOUND, "Reserva nâo encontrada: " + id));

            reservation.setDeletedAt(Instant.now());
            reservation.setDeleted(true);

            reservationRepository.save(reservation);

        } catch (DataIntegrityViolationException e) {
            throw new DatabaseException("Integrity violation");
        }
    }

    //Atualizar reserva
    @Transactional
    public ReservationDTO update(ReservationDTO dto) {
        UserDTO loggedUser = (UserDTO) SecurityContextHolder.getContext().getAuthentication().getDetails();
        User userEntity = userRepository.getReferenceById(loggedUser.getId());


        Boolean isAdmin = userEntity.getRoles().stream().filter(r->r.getName().equals("ADMIN")).count() >0;



        Reservation currentReservation = reservationRepository.findById(dto.getId())
                .orElseThrow(() -> new ResponseStatusException(NOT_FOUND));

        if(!isAdmin && currentReservation.getUser().getId() != userEntity.getId()){
            throw new ResponseStatusException(FORBIDDEN);
        }
        currentReservation.setDateInitial(dto.getDateInitial());
        currentReservation.setDateFinal(dto.getDateFinal());
        currentReservation.setLand(dto.getLand().toEntity());


        Reservation updateReservation = reservationRepository.save(currentReservation);
        return new ReservationDTO(updateReservation);
    }




    //Filtrar reservas por id de usuário
    @Transactional(readOnly = true)
    public List<ReservationDTO> findyAllUser(Integer idUser) {
        Optional<User> user = userRepository.findById(idUser);
        user.orElseThrow(()->new ResourceNotFoundException("Usuário não encontrado"));

        List<Reservation> reservations = reservationRepository.findByUser(user.get());

        return reservations
                .stream()
                .map(r -> new ReservationDTO(r))
                .collect(Collectors.toList());
    }

    // Filtro de reservas por id de terreno
    @Transactional(readOnly = true)
    public List<ReservationDTO> findAllByLands(Integer idLand){
        Optional<Land> land = landRepository.findById(idLand);
        //land.orElseThrow(()->new ResourceNotFoundException("Terreno não encontrado"));

        List<Reservation> reservations = reservationRepository.findByLand(land.get());
        return reservations
                .stream()
                .map(r->new ReservationDTO(r))
                .collect(Collectors.toList());
    }
}
