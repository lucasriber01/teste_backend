/*package com.dhbrasil.projetoIntegrador.AlugaVerso.config;

import com.dhbrasil.projetoIntegrador.AlugaVerso.model.*;
import com.dhbrasil.projetoIntegrador.AlugaVerso.repository.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;

import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.Set;
@Configuration
@Profile("test")
public class TestConfig implements CommandLineRunner {

    @Autowired
    private CategoryRepository categoryRepository;

    @Autowired
    private AttributesRepository attributesRepository;

    @Autowired
    private MetaverseRepository metaverseRepository;

    @Autowired
    private ImagesRepository imagesRepository;

    @Autowired
    private LandRepository landRepository;

    @Autowired
    private ReservationRepository reservationRepository;

    @Autowired
    private FunctionRepository functionRepository;

    @Autowired
    private ClientRepository clientRepository;

    @Override
    public void run(String... args) throws Exception {

        Category c1 = new Category(null, "Metaverso 1", "https://cdn.discordapp.com/attachments/958381134205567073/980865408863182898/unknown.png", "Espaço para reuniões");
        Category c2 = new Category(null, "Metaverso 2", "https://st4.depositphotos.com/1793519/23667/i/600/depositphotos_236672870-stock-photo-3d-render-visualization-of-a.jpg", "Espaço para filmes");
        Category c3 = new Category(null, "Metaverso 3", "https://veja.abril.com.br/wp-content/uploads/2022/02/metaverso.jpg", "Espaço para compras");
        Category c4 = new Category(null, "Metaverso 4", "https://img.olhardigital.com.br/wp-content/uploads/2021/12/Pessoas-no-metaverso.jpg", "Espaço para interações casuais");
        Category c5 = new Category(null, "Metaverso 5", "https://diariodonordeste.verdesmares.com.br/image/contentid/policy:1.3219212:1650310166/Igreja-no-metaverso.jpg?f=default&$p$f=04a14e3", "Espaço para celebrações religiosas");
        categoryRepository.saveAll(Arrays.asList(c1, c2, c3, c4, c5));

        Attributes a1 = new Attributes(null, "Icone casa", "icone casa");
        Attributes a2 = new Attributes(null, "Icone cancelar", "icone cancelar");
        Attributes a3 = new Attributes(null, "Icone comércio", "icone comercio");
        Attributes a4 = new Attributes(null, "Icone atividades culturais", "icone atv culturais");
        attributesRepository.saveAll(Arrays.asList(a1, a2, a3, a4));

        Metaverse m1 = new Metaverse(null, "Roblox Corporarion");
        Metaverse m2 = new Metaverse(null, "Microsoft");
        Metaverse m3 = new Metaverse(null, "NVIDIA");
        Metaverse m4 = new Metaverse(null, "Meta");
        Metaverse m5 = new Metaverse(null, "Decentraland");
        metaverseRepository.saveAll(Arrays.asList(m1, m2, m3, m4, m5));

        Images i1 = new Images( "Imagem A", "Imagem A");
        Images i2 = new Images( "Imagem B", "Imagem B");
        Images i3 = new Images( "Imagem C", "Imagem C");
        Images i4 = new Images( "Imagem D", "Imagem D");

        Land l1 = new Land(null, "Terreno 1", "Terreno no metaverso 1", "10", "20", 320.0);
        l1.setMetaverse(m1);
        l1.setCategory(c1);
        l1.setImages(Set.of(i1, i2));
        l1 = landRepository.save(l1);

        Land l2 = new Land(null, "Terreno 2", "Terreno no metaverso 1", "10", "20", 320.0);
        l2.setMetaverse(m2);
        l2.setCategory(c2);
        l2.setImages(Set.of(i3, i4));
        l2 = landRepository.save(l2);

        Function f1 = new Function(null, "Operador");
        functionRepository.save(f1);

        Client client1 = new Client();
        client1.setName("Teodoro");
        client1.setLastName("Alves");
        client1.setEmail("teodoro@gmail.com");
        client1.setPassword("123123");
        client1.setFunction(f1);
        clientRepository.save(client1);

        Reservation reservation = new Reservation();
        reservation.setClient(new Client(null, "A", "B", "ab", "ab123", f1));
        reservation.setDateInitial(new Date(2022 - 1900, 06 - 01, 05));
        reservation.setDateFinal(new Date(2022 - 1900, 06 - 01, 10));
        reservation.setLand(l2);

        reservationRepository.save(reservation);

        List<Land> lands = landRepository.findByMetaverseAndReservationDates("Microsoft",
                new Date(2022 - 1900, 05 - 01, 01),
                new Date(2022 - 1900, 05 - 01, 30));

        System.out.println("\n\nLands encontrados na data: " + lands);

    }
}*/

