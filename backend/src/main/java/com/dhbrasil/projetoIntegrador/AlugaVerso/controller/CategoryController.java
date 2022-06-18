package com.dhbrasil.projetoIntegrador.AlugaVerso.controller;

import com.dhbrasil.projetoIntegrador.AlugaVerso.dto.CategoryDTO;
import com.dhbrasil.projetoIntegrador.AlugaVerso.service.CategoryService;
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
@RequestMapping("/categories")
public class CategoryController {

   @Autowired
    private CategoryService categoryService;

   @PostMapping
   public ResponseEntity<CategoryDTO> insert(@RequestBody CategoryDTO dto) {
       dto = categoryService.insert(dto);
       URI uri = ServletUriComponentsBuilder.fromCurrentRequest().path("/{id}")
               .buildAndExpand(dto.getId()).toUri();
       return ResponseEntity.created(uri).body(dto);
   }
    // Buscar todos 'convencional'
//   @GetMapping
//   public ResponseEntity<List<CategoryDTO>> findAll(){
//       List<CategoryDTO> list = categoryService.findAll();
//       return ResponseEntity.ok().body(list);
//   }

   //Busca paginada
    @GetMapping
    public ResponseEntity<Page<CategoryDTO>> findAll(
            @RequestParam(value = "page", defaultValue = "0") Integer page,
            @RequestParam(value = "linesPerPage", defaultValue = "12") Integer linesPerPage,
            @RequestParam(value = "direction", defaultValue = "ASC") String direction,
            @RequestParam(value = "orderBy", defaultValue = "name") String orderBy

    ){
        PageRequest pageRequest = PageRequest.of(page, linesPerPage, Sort.Direction.valueOf(direction), orderBy);

        Page<CategoryDTO> list = categoryService.findAllPaged(pageRequest);
        return ResponseEntity.ok().body(list);
    }

    @PutMapping(value = "/{id}")
    public ResponseEntity<CategoryDTO> update(@PathVariable Integer id, @RequestBody CategoryDTO dto) {
        dto.setId(id);
        CategoryDTO obj = categoryService.update(dto);
        return ResponseEntity.ok().body(obj);
    }

    @DeleteMapping(value = "/{id}")
    public ResponseEntity<Void> delete(@PathVariable Integer id){
       categoryService.delete(id);
       return ResponseEntity.noContent().build();
    }
}
