package com.dhbrasil.projetoIntegrador.AlugaVerso.controller;


import com.dhbrasil.projetoIntegrador.AlugaVerso.dto.CategoryDTO;
import com.dhbrasil.projetoIntegrador.AlugaVerso.dto.MetaverseDTO;
import com.dhbrasil.projetoIntegrador.AlugaVerso.service.MetaverseService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import java.net.URI;
import java.util.List;

@RestController
@RequestMapping("/metaverses")
public class MetaverseController {

    @Autowired
    private MetaverseService metaverseService;

    //Criar cidades
    @PostMapping
    public ResponseEntity<MetaverseDTO> createMetaverse(@RequestBody MetaverseDTO dto) {
        dto = metaverseService.insert(dto);
        URI uri = ServletUriComponentsBuilder.fromCurrentRequest().path("/{id}")
                .buildAndExpand(dto.getId()).toUri();
        return ResponseEntity.created(uri).body(dto);
    }

    //Listar todas as cidades
//    @GetMapping
//   public ResponseEntity<List<MetaverseDTO>> listMetaverse(){
//       List<MetaverseDTO> list = metaverseService.findAll();
//       return ResponseEntity.ok().body(list);
//   }

    //Lista paginada das cidaddes
    @GetMapping
    public ResponseEntity<Page<MetaverseDTO>> findAllPaged(
            @RequestParam(value = "page", defaultValue = "0") Integer page,
            @RequestParam(value = "linesPerPage", defaultValue = "12") Integer linesPerPage,
            @RequestParam(value = "direction", defaultValue = "ASC") String direction,
            @RequestParam(value = "orderBy", defaultValue = "name") String orderBy

    ){
        PageRequest pageRequest = PageRequest.of(page, linesPerPage, Sort.Direction.valueOf(direction), orderBy);

        Page<MetaverseDTO> list = metaverseService.findAllPaged(pageRequest);
        return ResponseEntity.ok().body(list);
    }

    //Atualizar cidade
    @PutMapping(value = "/{id}")
    public ResponseEntity<MetaverseDTO> updateMetaverse(@PathVariable Integer id, @RequestBody MetaverseDTO dto) {
        dto.setId(id);
        MetaverseDTO obj = metaverseService.update(dto);
        return ResponseEntity.ok().body(obj);
    }

    //Deletar cidade
    @DeleteMapping(value = "/{id}")
    public ResponseEntity<Void> delete(@PathVariable Integer id){
        metaverseService.delete(id);
        return ResponseEntity.noContent().build();
    }
}
