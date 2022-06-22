package com.dhbrasil.projetoIntegrador.AlugaVerso.service;

import com.dhbrasil.projetoIntegrador.AlugaVerso.dto.MetaverseDTO;
import com.dhbrasil.projetoIntegrador.AlugaVerso.model.Metaverse;
import com.dhbrasil.projetoIntegrador.AlugaVerso.repository.MetaverseRepository;
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
public class MetaverseService {

    @Autowired
    private MetaverseRepository metaverseRepository;

    //Listar todas as cidades
    @Transactional(readOnly = true)
    public List<MetaverseDTO> findAll(){
        List<Metaverse> list = metaverseRepository.findAll();
        return list.stream().map(x -> new MetaverseDTO(x)).collect(Collectors.toList());
    }

    //Lista paginada das cidaddes
    @Transactional(readOnly = true)
    public Page<MetaverseDTO> findAllPaged(PageRequest pageRequest){
        Page<Metaverse> list = metaverseRepository.findAll(pageRequest);
        return list.map(x -> new MetaverseDTO(x));
    }

    //Criar cidades
    @Transactional
    public MetaverseDTO insert(MetaverseDTO metaverseDTO){
        Metaverse metaverse = metaverseRepository.save(metaverseDTO.toEntity());
        return new MetaverseDTO(metaverse);
    }

    //Atualizar cidade
    @Transactional
    public MetaverseDTO update(MetaverseDTO dto){
        Metaverse currentMetaverse = metaverseRepository.findById(dto.getId())
                .orElseThrow(() -> new ResponseStatusException(NOT_FOUND));

        currentMetaverse.setName(dto.getName());
        currentMetaverse.setImagemUrl(dto.getImagemUrl());
        Metaverse updatedMetaverse = metaverseRepository.save(currentMetaverse);
        return new MetaverseDTO(updatedMetaverse);
    }

    @Transactional
    public void delete(Integer id){
        try{
            metaverseRepository.deleteById(id);
        } catch (EmptyResultDataAccessException e){
            throw new ResponseStatusException(NOT_FOUND, "Categoria nâo encontrada: "+id);
        }
        catch (DataIntegrityViolationException e) {
            throw new DatabaseException("Integrity violation");
        }
    }
}
