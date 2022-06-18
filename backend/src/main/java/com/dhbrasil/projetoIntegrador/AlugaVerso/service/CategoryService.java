package com.dhbrasil.projetoIntegrador.AlugaVerso.service;

import com.dhbrasil.projetoIntegrador.AlugaVerso.dto.CategoryDTO;
import com.dhbrasil.projetoIntegrador.AlugaVerso.model.Category;
import com.dhbrasil.projetoIntegrador.AlugaVerso.repository.CategoryRepository;
import com.dhbrasil.projetoIntegrador.AlugaVerso.service.exceptions.DatabaseException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import java.util.List;
import java.util.stream.Collectors;

import static org.springframework.http.HttpStatus.NOT_FOUND;

@Service
public class CategoryService {

    @Autowired
    private CategoryRepository categoryRepository;

    @Transactional
    public CategoryDTO insert(CategoryDTO categoryDTO){
        Category category = categoryRepository.save(categoryDTO.toEntity());
        return new CategoryDTO(category);
    }

    @Transactional(readOnly = true)
    public List<CategoryDTO> findAll(){
        List<Category> list = categoryRepository.findAll();
        return list.stream().map(x -> new CategoryDTO(x)).collect(Collectors.toList());
    }

    //Busca paginada
    @Transactional(readOnly = true)
    public Page<CategoryDTO> findAllPaged(PageRequest pageRequest){
        Page<Category> list = categoryRepository.findAll(pageRequest);
        return list.map(x -> new CategoryDTO(x));
    }

    @Transactional
    public CategoryDTO update(CategoryDTO dto){
        Category currentCategory = categoryRepository.findById(dto.getId())
                .orElseThrow(() -> new ResponseStatusException(NOT_FOUND));

        currentCategory.setName(dto.getName());
        currentCategory.setImagemUrl(dto.getImagemUrl());
        currentCategory.setDescription(dto.getDescription());

        Category updatedCategory = categoryRepository.save(currentCategory);
        return new CategoryDTO(updatedCategory);
    }

    @Transactional
    public void delete(Integer id){
        try{
            categoryRepository.deleteById(id);
        } catch (EmptyResultDataAccessException e){
            throw new ResponseStatusException(NOT_FOUND, "Categoria nâo encontrada: "+id);
        }
        catch (DataIntegrityViolationException e) {
            throw new DatabaseException("Integrity violation");
        }
    }
}
