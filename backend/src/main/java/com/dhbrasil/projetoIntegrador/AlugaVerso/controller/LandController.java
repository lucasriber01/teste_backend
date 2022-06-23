package com.dhbrasil.projetoIntegrador.AlugaVerso.controller;

import com.dhbrasil.projetoIntegrador.AlugaVerso.dto.CategoryDTO;
import com.dhbrasil.projetoIntegrador.AlugaVerso.dto.LandDTO;
import com.dhbrasil.projetoIntegrador.AlugaVerso.dto.LandListDTO;
import com.dhbrasil.projetoIntegrador.AlugaVerso.dto.LandResponseDTO;
import com.dhbrasil.projetoIntegrador.AlugaVerso.repository.LandRepository;
import com.dhbrasil.projetoIntegrador.AlugaVerso.service.LandService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import javax.validation.Valid;
import java.net.URI;
import java.util.Date;
import java.util.List;

@RestController
@RequestMapping("/lands")
public class LandController {

    @Autowired
    private LandService landService;

    @Autowired
    private LandRepository landRepository;

    //Cadastrar terreno
    @PostMapping
    public ResponseEntity<LandDTO> createdLand(@Valid @RequestBody LandDTO dto) {
        Integer id  = landService.insert(dto);
        LandDTO landDTO = new LandDTO(landRepository.findById(id).get());

        URI uri = ServletUriComponentsBuilder.fromCurrentRequest().path("/{id}")
                .buildAndExpand(dto.getId()).toUri();
        return ResponseEntity.created(uri).body(landDTO);
    }

    //Lista paginada das terrenos
    @GetMapping
    public ResponseEntity<Page<LandDTO>> findAllPaged(
            @RequestParam(value = "page", defaultValue = "0") Integer page,
            @RequestParam(value = "linesPerPage", defaultValue = "8") Integer linesPerPage,
            @RequestParam(value = "direction", defaultValue = "ASC") String direction,
            @RequestParam(value = "orderBy", defaultValue = "name") String orderBy

    ){
        PageRequest pageRequest = PageRequest.of(page, linesPerPage, Sort.Direction.valueOf(direction), orderBy);

        Page<LandDTO> list = landService.findAllPaged(pageRequest);
        return ResponseEntity.ok().body(list);
    }

    //Listar todas os terrenos
//    @GetMapping
//   public ResponseEntity<List<LandDTO>> listLand(){
//       List<LandDTO> list = landService.findAll();
//       return ResponseEntity.ok().body(list);
//   }

    //Busca por id
    @GetMapping(value = "/{id}")
    public ResponseEntity<LandListDTO> searchLandId(@PathVariable Integer id){
        LandListDTO landDTO = landService.findById(id);
        return ResponseEntity.ok().body(landDTO);
    }

    //Deletar terreno
    @DeleteMapping(value = "/{id}")
    public ResponseEntity<Void> delete(@PathVariable Integer id){
        landService.delete(id);
        return ResponseEntity.noContent().build();
    }

    //Atualizar terreno
    @PutMapping(value = "/{id}")
    public ResponseEntity<LandDTO> updateLand( @PathVariable Integer id, @Valid @RequestBody LandDTO dto) {
        dto.setId(id);
        LandDTO obj = landService.update(dto);
        return ResponseEntity.ok().body(obj);
    }
    //Busca por cidade (metaverse) listByMetaverse
    @GetMapping(value = "/search/metaverse")
    public List<LandDTO>listByMetaverse(@RequestParam Integer idMetaverse){
        return landService.listByMetaverse(idMetaverse);
    }

    //Busca por categoria listByCategory
    @GetMapping(value = "/search/category")
    public List<LandDTO>listByCategory(@RequestParam Integer idCategory){
        return landService.listByCategory(idCategory);
    }

    // Filtro por cidade e intervalo de data
    @GetMapping(value = "/search")
    public List<LandResponseDTO> findByMetaverseAndReservationDates(@RequestParam("metaverseName") String metaverseName,
                                                                    @RequestParam("initialDate") @DateTimeFormat(iso = DateTimeFormat.ISO.DATE) Date initialDate,
                                                                    @RequestParam("endDate") @DateTimeFormat(iso = DateTimeFormat.ISO.DATE) Date endDate){
        return landService.findByMetaverseAndReservationDates(metaverseName, initialDate, endDate);
    }

    // Filtro intervalo de data
    @GetMapping(value = "/search/dates")
    public List<LandResponseDTO> findByReservationDates(@RequestParam("initialDate") @DateTimeFormat(iso = DateTimeFormat.ISO.DATE) Date initialDate,
                                                        @RequestParam("endDate") @DateTimeFormat(iso = DateTimeFormat.ISO.DATE) Date endDate){
        return landService.findByReservationDates(initialDate, endDate);
    }
}

