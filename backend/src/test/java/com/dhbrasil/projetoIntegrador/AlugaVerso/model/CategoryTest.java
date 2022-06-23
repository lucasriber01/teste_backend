package com.dhbrasil.projetoIntegrador.AlugaVerso.model;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

import org.junit.jupiter.api.Test;

public class CategoryTest {
	
	
	@Test
	public void CategoryInstance() {
		Category categoria = new Category(1,"Terreno 3","https://images.adsttc.com/media/images/61dc/9695/23d7/e841/555d/d83c/large_jpg/decentraland-fashion-street.jpg?1641846425","Terreno metaverso Decentraland ");

	}

	@Test
	public void setCategory() {
		Category categoria = new Category();
		categoria.setId(1);
		assertEquals(1, categoria.getId());
		
		categoria.setName("Terreno 3");
		assertEquals("Terreno 3", categoria.getName());
		
		categoria.setDescription("Terreno metaverso Decentraland ");
		assertEquals("Terreno metaverso Decentraland ", categoria.getDescription());
		
		categoria.setImagemUrl("https://distrito.me/wp-content/uploads/2021/10/metaverso-scaled.jpg");
		assertEquals("https://distrito.me/wp-content/uploads/2021/10/metaverso-scaled.jpg", categoria.getImagemUrl());

		//categoria.setDeleted(false);
		assertFalse(categoria.isDeleted());
		//assertEquals(false, categoria.getDeletedAt());

		categoria.setDeletedAt(null);
		categoria.isDeleted();
	}
	
	@Test
	public void getCategory() {
		Category categoria = new Category(1,"Terreno 3","https://images.adsttc.com/media/images/61dc/9695/23d7/e841/555d/d83c/large_jpg/decentraland-fashion-street.jpg?1641846425","Terreno metaverso Decentraland ");
		categoria.getId();	
		categoria.getName();
		categoria.getDescription();
		categoria.getImagemUrl();
		categoria.getDeletedAt();
		categoria.getUpdatedAt();
	}
	
	

	

	

}
