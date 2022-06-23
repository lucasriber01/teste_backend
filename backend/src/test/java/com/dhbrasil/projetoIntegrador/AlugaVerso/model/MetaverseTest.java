package com.dhbrasil.projetoIntegrador.AlugaVerso.model;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

public class MetaverseTest {
	
	
	@Test
	public void MetaverseInstance() {
		Metaverse obj = new Metaverse();

	}
	
	@Test
	public void MetaverseInstance2() {
		Metaverse obj = new Metaverse(1,"Metaverse2", "test.jpg");

	}

	@Test
	public void setMetaverse() {
		Metaverse obj = new Metaverse();
		obj.setId(1);
		assertEquals(1, obj.getId());
		
		obj.setName("Terreno 3");
		assertEquals("Terreno 3", obj.getName());
		
		obj.setDeletedAt(null);
		assertEquals(null, obj.getDeletedAt());
		
		
	}
	

	

	

}
