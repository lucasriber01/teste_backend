package com.dhbrasil.projetoIntegrador.AlugaVerso.service;


import com.dhbrasil.projetoIntegrador.AlugaVerso.dto.LandDTO;
import com.dhbrasil.projetoIntegrador.AlugaVerso.model.Land;
import com.dhbrasil.projetoIntegrador.AlugaVerso.repository.CategoryRepository;
import com.dhbrasil.projetoIntegrador.AlugaVerso.repository.ImagesRepository;
import com.dhbrasil.projetoIntegrador.AlugaVerso.repository.LandRepository;
import com.dhbrasil.projetoIntegrador.AlugaVerso.service.exceptions.DatabaseException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import java.util.Date;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

import static org.springframework.http.HttpStatus.NOT_FOUND;

@Service
public class LandService {

    @Autowired
    private LandRepository landRepository;

    @Autowired
    private ImagesRepository imagesRepository;

    @Autowired
    private CategoryRepository categoryRepository;

    //Cadastrar terreno
    @Transactional
    public Integer insert(LandDTO landDTO) {
        Land land = landRepository.save(landDTO.toEntity());
        return land.getId();
    }

    //Lista paginada das terrenos
    @Transactional(readOnly = true)
    public Page<LandDTO> findAllPaged(PageRequest pageRequest){
        Page<Land> list = landRepository.findAll(pageRequest);
        return list.map(x -> new LandDTO(x));
    }

    //Listar todas os terrenos
    @Transactional(readOnly = true)
    public List<LandDTO> findAll(){
        List<Land> list = landRepository.findAll();
        return list.stream().map(x -> new LandDTO(x)).collect(Collectors.toList());
    }

    //Busca por id
    @Transactional(readOnly = true)
    public LandDTO findById(Integer id){
        Optional<Land> landObj = landRepository.findById(id);
        Land land = landObj.orElseThrow(()-> new ResponseStatusException(NOT_FOUND));
        return new LandDTO(land);
    }

    //Deletar terreno
    @Transactional
    public void delete(Integer id){
        try{
            landRepository.deleteById(id);
        } catch (EmptyResultDataAccessException e){
            throw new ResponseStatusException(NOT_FOUND, "Terreno nâo encontrada: "+id);
        }
        catch (DataIntegrityViolationException e) {
            throw new DatabaseException("Integrity violation");
        }
    }

    //Atualizar terreno
    @Transactional
    public LandDTO update(LandDTO dto){
        Land currentLand = landRepository.findById(dto.getId())
                .orElseThrow(() -> new ResponseStatusException(NOT_FOUND));

        currentLand.setName(dto.getName());
        currentLand.setDescription(dto.getDescription());
        currentLand.setLocalizationX(dto.getLocalizationX());
        currentLand.setLocalizationY(dto.getLocalizationY());
        currentLand.setPrice(dto.getPrice());
        currentLand.setCategory(dto.getCategory().toEntity());
        currentLand.setMetaverse(dto.getMetaverse().toEntity());

        Land updateLand = landRepository.save(currentLand);
        return new LandDTO(updateLand);
    }

    //Busca por cidade (metaverse)
    @Transactional(readOnly = true)
    public List<LandDTO> listByMetaverse(Integer idMetaverse) {

        return landRepository.findByMetaverseId(idMetaverse)
                .stream()
                .map(p -> new LandDTO(p))
                .collect(Collectors.toList());
    }
    //Busca por categoria
    @Transactional(readOnly = true)
    public List<LandDTO> listByCategory(Integer idCategory) {

        return landRepository.findByCategoryId(idCategory)
                .stream()
                .map(p -> new LandDTO(p))
                .collect(Collectors.toList());
    }

    // Filtro por cidade e intervalo de data
    @Transactional(readOnly = true)
    public List<LandDTO> findByMetaverseAndReservationDates(String metaverse, Date initialDate, Date endDate){
        return landRepository.findByMetaverseAndReservationDates(metaverse, initialDate, endDate)
                .stream()
                .map(land -> new LandDTO(land))
                .collect(Collectors.toList());
    }
}
