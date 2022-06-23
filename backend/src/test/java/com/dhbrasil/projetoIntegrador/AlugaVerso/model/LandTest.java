package com.dhbrasil.projetoIntegrador.AlugaVerso.model;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

public class LandTest {
	
	
	@Test
	public void LandInstance() {
		Land obj = new Land();

	}
	
	@Test
	public void LandInstance2() {
		Land obj = new Land(1,"Metaverse2","Ilha particular localizada no Descentraland",  "37.8095,-122.4101","51.490025,6.874931", 550.00);
	}
	
	@Test
	public void LandInstance3() {
		Land obj = new Land(2, "Metaverso2", "Casa servidor Descrentraland", "37.8575,-122", "37.0888", 3.50000, null, null, null, null);
	}

	@Test
	public void setLand() {
		Land obj = new Land();
		obj.setId(1);
		assertEquals(1, obj.getId());
		
		obj.setName("Terreno 3");
		assertEquals("Terreno 3", obj.getName());
		
		
		obj.setDescription("Servidor Descrentraland");
		assertEquals("Servidor Descrentraland", obj.getDescription());
		
		obj.setLocalizationX("37.8575,-122");
		assertEquals("37.8575,-122", obj.getLocalizationX());
		
		obj.setLocalizationY("37.8575,-122");
		assertEquals("37.8575,-122", obj.getLocalizationY());
		
		
		obj.setDeletedAt(null);
		assertEquals(null, obj.getDeletedAt());
		
		
	}
	

	

	

}
