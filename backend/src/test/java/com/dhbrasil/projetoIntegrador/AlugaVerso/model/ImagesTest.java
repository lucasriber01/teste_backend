package com.dhbrasil.projetoIntegrador.AlugaVerso.model;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

public class ImagesTest {

	@Test
	public void SetImages() {
		Images img = new Images();
		img.setId(1);
		assertEquals(1, img.getId());
		
		img.setTitle("Metaverso 001");
		assertEquals("Metaverso 001", img.getTitle());
		
		
		img.setUrl("https://distrito.me/wp-content/uploads/2021/10/metaverso-scaled.jpg");
		assertEquals("https://distrito.me/wp-content/uploads/2021/10/metaverso-scaled.jpg", img.getUrl());
		
	}
	
	
	@Test
	public void ImagesInstance() {
		Images img = new Images();	
	}
	
	@Test
	public void ImagesInstance2() {
		Images img = new Images("Metaverse 02", "https://distrito.me/wp-content/uploads/2021/10/metaverso-scaled.jpg");
	}
	
	@Test
	public void ImagesInstance3() {
		Images img = new Images(1, "Metaverse 02" , "https://distrito.me/wp-content/uploads/2021/10/metaverso-scaled.jpg");	
	}
	

	
	

}
