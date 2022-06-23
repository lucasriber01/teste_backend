package com.dhbrasil.projetoIntegrador.AlugaVerso.model;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

public class AttributesTest {

	@Test
	public void SetCategoryInstance() {
		Attributes atributos = new Attributes();
		atributos.setId(1);
		assertEquals(1, atributos.getId());
		
		
		atributos.setName("Metaverso 2");
		assertEquals("Metaverso 2", atributos.getName());

		atributos.setIcon("https://distrito.me/wp-content/uploads/2021/10/metaverso-scaled.jpg");
		assertEquals("https://distrito.me/wp-content/uploads/2021/10/metaverso-scaled.jpg", atributos.getIcon());

		atributos.setDeletedAt(null);
		assertEquals(null, atributos.getDeletedAt());
		
		atributos.getCreatedAt();
		atributos.getUpdatedAt();
		
		
	}
	
	@Test
	public void CategoryInstance() {

		Attributes atributos = new Attributes(1,"Metaverso 2", "https://distrito.me/wp-content/uploads/2021/10/metaverso-scaled.jpg" );

	}
	
	

}
