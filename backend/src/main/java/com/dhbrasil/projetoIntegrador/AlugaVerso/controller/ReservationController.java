package com.dhbrasil.projetoIntegrador.AlugaVerso.controller;

import com.dhbrasil.projetoIntegrador.AlugaVerso.dto.LandDTO;
import com.dhbrasil.projetoIntegrador.AlugaVerso.dto.ReservationDTO;
import com.dhbrasil.projetoIntegrador.AlugaVerso.repository.LandRepository;
import com.dhbrasil.projetoIntegrador.AlugaVerso.repository.ReservationRepository;
import com.dhbrasil.projetoIntegrador.AlugaVerso.service.LandService;
import com.dhbrasil.projetoIntegrador.AlugaVerso.service.ReservationService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import javax.validation.Valid;
import java.net.URI;
import java.util.List;

@RestController
@RequestMapping("/reservation")
public class ReservationController {

    @Autowired
    private ReservationService reservationService;

    @Autowired
    private ReservationRepository reservationRepository;

    //Cadastrar reserva
    @PostMapping
    public ResponseEntity<ReservationDTO> createdReservation( @RequestBody ReservationDTO dto) {
        Integer id  = reservationService.createReservation(dto);
        ReservationDTO reservationDTO = new ReservationDTO(reservationRepository.findById(id).get());
        URI uri = ServletUriComponentsBuilder.fromCurrentRequest().path("/{id}")
                .buildAndExpand(dto.getId()).toUri();
        return ResponseEntity.created(uri).body(reservationDTO);
    }

    //Lista paginada das reservas
//    @GetMapping
//    public ResponseEntity<Page<ReservationDTO>> findAllPaged(
//            @RequestParam(value = "page", defaultValue = "0") Integer page,
//            @RequestParam(value = "linesPerPage", defaultValue = "8") Integer linesPerPage,
//            @RequestParam(value = "direction", defaultValue = "ASC") String direction,
//            @RequestParam(value = "orderBy", defaultValue = "name") String orderBy
//
//    ){
//        PageRequest pageRequest = PageRequest.of(page, linesPerPage, Sort.Direction.valueOf(direction), orderBy);
//
//        Page<ReservationDTO> list = reservationService.findAllPaged(pageRequest);
//        return ResponseEntity.ok().body(list);
//    }

    //Listar todas as reservas
    @GetMapping
   public ResponseEntity<List<ReservationDTO>> listReservation(){
       List<ReservationDTO> list = reservationService.findAll();
       return ResponseEntity.ok().body(list);
   }

    //Busca por id
    @GetMapping(value = "/{id}")
    public ResponseEntity<ReservationDTO> searchReservationId(@PathVariable Integer id){
        ReservationDTO reservationDTO = reservationService.findById(id);
        return ResponseEntity.ok().body(reservationDTO);
    }

    //Deletar reserva
    @DeleteMapping(value = "/{id}")
    public ResponseEntity<Void> delete(@PathVariable Integer id){
        reservationService.delete(id);
        return ResponseEntity.noContent().build();
    }

    //Atualizar reserva
    @PutMapping(value = "/{id}")
    public ResponseEntity<ReservationDTO> updateLand( @PathVariable Integer id, @Valid @RequestBody ReservationDTO dto) {
        dto.setId(id);
        ReservationDTO obj = reservationService.update(dto);
        return ResponseEntity.ok().body(obj);
    }

    //Filtrar reservas por id de usuário
    @GetMapping(value = "/filter/user")
    public List<ReservationDTO> findyAllUser(@RequestParam Integer idUser){
        return reservationService.findyAllUser(idUser);
    }

    // Filtro de reservas por id de terreno
    @GetMapping(value = "/filter/lands")
    public List<ReservationDTO> findAllByLands(@RequestParam Integer idLand){
        return  reservationService.findAllByLands(idLand);
    }
}

