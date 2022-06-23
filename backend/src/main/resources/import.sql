INSERT INTO category (id, name, imagem_Url, description, created_At, deleted) VALUES (default, 'Casamento', 'https://cdn.discordapp.com/attachments/976896514699976815/976896617246490654/1440x810_cmsv2_e07d6986-7d96-5d7f-a495-a46f85730765-6447250.jpg', 'Espaços destinados para a experiência imersiva e única na celebração da união entre duas pessoas', NOW(), FALSE);
INSERT INTO category (id, name, imagem_Url, description, created_At, deleted) VALUES (default,'Festa e Show', 'https://cdn.discordapp.com/attachments/976896514699976815/976896617527541781/amnesia-metaverse.png', 'Locais destinados para a curtição com a galera de várias partes do mundo.', NOW(), FALSE);
INSERT INTO category (id, name, imagem_Url, description, created_At, deleted) VALUES (default, 'Divulgação', 'https://cdn.discordapp.com/attachments/976896514699976815/981173219396575282/unknown.jpg', 'Faça parte do futuro e garanta o seu ponto de divulgação nos pontos mais valorizados do metaverso.', NOW(), FALSE);
INSERT INTO category (id, name, imagem_Url, description, created_At, deleted) VALUES (default, 'Lazer e recreação', 'https://cdn.discordapp.com/attachments/976896514699976815/976896617246490654/1440x810_cmsv2_e07d6986-7d96-5d7f-a495-a46f85730765-6447250.jpg', 'Esteja um passo a frente ao participar e interagir nos espaços culturais destinados ao lazer e recreação. Divirta-se nas áreas esportivas. Fique por dentro das exposições dos NFTs', NOW(), FALSE);

INSERT INTO metaverse (id, name, imagem_Url, created_At, deleted) VALUES (default, 'Decentraland', 'https://cdn.discordapp.com/attachments/976896514699976815/984124121266941952/metaverse-decentraland.png', NOW(), FALSE);
INSERT INTO metaverse (id, name, imagem_Url, created_At, deleted) VALUES (default, 'Sandbox', 'https://cdn.discordapp.com/attachments/976896514699976815/984124137230458880/metaverse-sandbox.png', NOW(), FALSE);

INSERT INTO attributes (id, name, icon, created_At, deleted) VALUES (default, 'Alta procura', 'https://cdn.discordapp.com/attachments/988791300784541696/988797045789835274/arrow-trend-up.svg', NOW(), FALSE);
INSERT INTO attributes (id, name, icon, created_At, deleted) VALUES (default, 'Próximo ao comércio', 'https://cdn.discordapp.com/attachments/976896514699976815/981183276263825418/carrinho-de-compras-comercio.svg', NOW(), FALSE);
INSERT INTO attributes (id, name, icon, created_At, deleted) VALUES (default, 'Cancelamento gratuito', 'https://cdn.discordapp.com/attachments/976896514699976815/981184521787559998/cancelamento-gratuito.svg', NOW(), FALSE);
INSERT INTO attributes (id, name, icon, created_At, deleted) VALUES (default, 'Atividades culturais', 'https://cdn.discordapp.com/attachments/976896514699976815/981184936054759424/atividades-culturais.svg', NOW(), FALSE);
INSERT INTO attributes (id, name, icon, created_At, deleted) VALUES (default, 'Eventos formais', 'https://cdn.discordapp.com/attachments/976896514699976815/981185247221788722/eventos-formais.svg', NOW(), FALSE);
INSERT INTO attributes (id, name, icon, created_At, deleted) VALUES (default, 'Terreno raro', 'https://cdn.discordapp.com/attachments/988791300784541696/988791425024000021/star.svg', NOW(), FALSE);
INSERT INTO attributes (id, name, icon, created_At, deleted) VALUES (default, 'Próximo de museus', 'https://cdn.discordapp.com/attachments/988791300784541696/988791833784123492/building-columns.svg', NOW(), FALSE);
INSERT INTO attributes (id, name, icon, created_At, deleted) VALUES (default, 'Próximo ao oceano', 'https://cdn.discordapp.com/attachments/988791300784541696/988793427145674752/water.svg', NOW(), FALSE);
INSERT INTO attributes (id, name, icon, created_At, deleted) VALUES (default, 'Espaço arborizado', 'https://cdn.discordapp.com/attachments/988791300784541696/988794681318072340/tree-city.svg', NOW(), FALSE);
INSERT INTO attributes (id, name, icon, created_At, deleted) VALUES (default, 'Ambiente musical', 'https://cdn.discordapp.com/attachments/988791300784541696/988796338231705620/music.svg', NOW(), FALSE);
INSERT INTO attributes (id, name, icon, created_At, deleted) VALUES (default, 'Próximo a monumento famoso', 'https://cdn.discordapp.com/attachments/988791300784541696/988796422570803220/monument.svg', NOW(), FALSE);

INSERT INTO land (id, name, description, localizationX, localizationY, price, category_id, metaverse_id, created_At, deleted) VALUES (default, 'Espaço para eventos formais ideal para casamento', 'Terreno bem localizado e próprio para eventos formais, principalmente, casamentos.', '-117', '-24', 1002.0, 1, 1, NOW(), FALSE);
INSERT INTO land (id, name, description, localizationX, localizationY, price, category_id, metaverse_id, created_At, deleted) VALUES (default, 'Fun', 'Espaço destinado para festas e shows..', '-70', '28', 937.0, 2, 1, NOW(), FALSE);
INSERT INTO land (id, name, description, localizationX, localizationY, price, category_id, metaverse_id, created_At, deleted) VALUES (default, 'Divulgue já!', 'Esteja um passo a frente. Anuncie a sua marca aqui. Ótimo local ao lado da estrada', '-65', '130', 521.0, 3, 1, NOW(), FALSE);
INSERT INTO land (id, name, description, localizationX, localizationY, price, category_id, metaverse_id, created_At, deleted) VALUES (default, 'Amplo terreno para divulgar e promover a sua marca.', 'On road opposite shopping district. Dois lotes na estrada em frente ao distrito comercial', '-101', '-21', 887.0, 3, 1, NOW(), FALSE);
INSERT INTO land (id, name, description, localizationX, localizationY, price, category_id, metaverse_id, created_At, deleted) VALUES (default, 'Promova atividades culturais e recreativas neste terreno raro.', 'Super Rare 2x1 Genesis Main Road Estate. (Super Raro 2x1 Genesis Main Road Estate)', '19', '-1', 798.0, 4, 1, NOW(), FALSE);
INSERT INTO land (id, name, description, localizationX, localizationY, price, category_id, metaverse_id, created_At, deleted) VALUES (default, 'Área projetada para recreação infantil. Muitos brinquedos.', 'Terreno bem localizado. Próximo ao Genesis PLaza. A criançada tem diversão garantida aqui', '-1', '15', 564.0, 4, 1, NOW(), FALSE);
INSERT INTO land (id, name, description, localizationX, localizationY, price, category_id, metaverse_id, created_At, deleted) VALUES (default, 'Ambiente próximo ao centro e aconchegante para cerimônias de casamento.', 'Procura um local de fácil acesso aos seus convidados? Está no terreno certo. Muito perto do centro, localização ideal para desenvolver ainda mais.', '-14', '-16', 752.0, 1, 1, NOW(), FALSE);
INSERT INTO land (id, name, description, localizationX, localizationY, price, category_id, metaverse_id, created_At, deleted) VALUES (default, 'Raridade para a divulgação de marcas.', 'Quer uma raridade para impulsionar a sua marca? Anuncie neste terreno.', '-134', '20', 630.0, 3, 1, NOW(), FALSE);
INSERT INTO land (id, name, description, localizationX, localizationY, price, category_id, metaverse_id, created_At, deleted) VALUES (default, 'Amplo espaço para a realização de festas e shows.', 'Três lotes na rua da moda ligados à estrada do distrito, irão captar o tráfego proveniente da estrada DCL.)', '-126', '-119', 1250.0, 2, 1, NOW(), FALSE);
INSERT INTO land (id, name, description, localizationX, localizationY, price, category_id, metaverse_id, created_At, deleted) VALUES (default, 'Ótima opção para investimento', 'Localização estratégica para divulgar seu negócio. Excelente opção para investimento com possibilidade de sublocação do espaço para outras divulgações', '34', '-167', 390.0, 3, 2, NOW(), FALSE);
INSERT INTO land (id, name, description, localizationX, localizationY, price, category_id, metaverse_id, created_At, deleted) VALUES (default, 'Ambiente para casamento', 'LA badalação que você precisa para o seu casamento. Próximo às principais vias e atrações culturais do Sandbox. Faça parte do futuro promovendo uma experiência única para seus convidados.', '52', '-88', 990.0, 1, 2, NOW(), FALSE);
INSERT INTO land (id, name, description, localizationX, localizationY, price, category_id, metaverse_id, created_At, deleted) VALUES (default, 'Atividades esportivas', 'Terreno privilegiado ao lado do terreno exclusivo do Sandbox. Local destinado para atividades esportivas ', '-150', '171', 799.0, 4, 2, NOW(), FALSE);
INSERT INTO land (id, name, description, localizationX, localizationY, price, category_id, metaverse_id, created_At, deleted) VALUES (default, 'Oportunidade de investimento', ' Deseja investir em um espaço mais reservado para promover aquelas festas boladonas? É a oportunidade ideal. ', '-15', '154', 280.0, 2, 2, NOW(), FALSE);
INSERT INTO land (id, name, description, localizationX, localizationY, price, category_id, metaverse_id, created_At, deleted) VALUES (default, 'Amplo terreno para festas e grandes eventos', ' Amplo terreno, próximo a diversos comércios e atividades culturais. ', '20', '-80', 700.0, 2, 2, NOW(), FALSE);
INSERT INTO land (id, name, description, localizationX, localizationY, price, category_id, metaverse_id, created_At, deleted) VALUES (default, 'Badalado terreno para divulgar seu negócio', ' Deseja impulsionar seu negócio? Reserve este terreno para divulgar sua empresa.', '12', '-78', 2088.0, 3, 2, NOW(), FALSE);
INSERT INTO land (id, name, description, localizationX, localizationY, price, category_id, metaverse_id, created_At, deleted) VALUES (default, 'Seu casamento é aqui', ' Um espaço totalmente pensado e desenhado para proporcionar uma experiência única e inesquecível tanto para os noivos quanto para os convidados. ', '163', '34', 1989.0, 1, 2, NOW(), FALSE);
INSERT INTO land (id, name, description, localizationX, localizationY, price, category_id, metaverse_id, created_At, deleted) VALUES (default, 'Várias atividades em um único só lugar', ' Aproveite o melhor do Metaverso. Ampla área construída para treinos esportivos e eventos culturais com exposições de NFTs. ', '12', '-78', 988.0, 4, 2, NOW(), FALSE);
INSERT INTO land (id, name, description, localizationX, localizationY, price, category_id, metaverse_id, created_At, deleted) VALUES (default, 'Faça a melhor festa no metaverso', ' Área cercada de atividades culturais. Terreno privilegiado.', '144', '-107', 1088.0, 2, 2, NOW(), FALSE);
INSERT INTO land (id, name, description, localizationX, localizationY, price, category_id, metaverse_id, created_At, deleted) VALUES (default, 'Encontre a diversão perfeita', ' Ambiente ideal para relaxar e descontrair. Aproveite o point do momento para fazer amigos e diversão. ', '190', '55', 1012.0, 4, 2, NOW(), FALSE);
INSERT INTO land (id, name, description, localizationX, localizationY, price, category_id, metaverse_id, created_At, deleted) VALUES (default, 'Estrutura projetada e pensada para realizar casamentos', 'Neste pedaço digital você conta com a estrutura projetada para celebrar cerimônias de casamento. Ambiente com decoração neutra e sem menção religiosa na decoração.', '-64', '190', 688.0, 1, 2, NOW(), FALSE);
INSERT INTO land (id, name, description, localizationX, localizationY, price, category_id, metaverse_id, created_At, deleted) VALUES (default, 'Parcel', 'Oportunidade para expandir seus negócios no metaverso. Terreno em área de franco crescimento. Local para realizar inesquecíveis shows e festas memoráveis.', '-51', '-111', 709.0, 2, 1, NOW(), FALSE);
INSERT INTO land (id, name, description, localizationX, localizationY, price, category_id, metaverse_id, created_At, deleted) VALUES (default, 'Genesis Park', 'Aproveite o amplo espaço desenhado e construído para atividades de lazer, esportivas e recreativas. Complexo esportivo para prática de esportes compatíveis com o mundo digital.', '-26', '-4', 829.0, 4, 1, NOW(), FALSE);
INSERT INTO land (id, name, description, localizationX, localizationY, price, category_id, metaverse_id, created_At, deleted) VALUES (default, 'Estate near Fashion', 'Terreno duplo localizado próximo a comércios. Área em rápido crescimento. Aproveite a oportunidade para divulgar seu negócio.', '-119', '-25', 1100.0, 3, 1, NOW(), FALSE);
INSERT INTO land (id, name, description, localizationX, localizationY, price, category_id, metaverse_id, created_At, deleted) VALUES (default, 'Arena Shows ', 'Confirme sua presença na estreia da Arena Shows. Espaço projetado para proporcionar as melhores experiências para os fãs de shows no metaverso. Preço promocional de inauguração.', '-21', '37', 559.0, 2, 1, NOW(), FALSE);
INSERT INTO land (id, name, description, localizationX, localizationY, price, category_id, metaverse_id, created_At, deleted) VALUES (default, 'Street Land', 'Já imaginou a criançada no metaverso? Essa oportunidade chegou. Venha conhecer o ambiente planejado para que a garotada experimente o futuro.', '-100', '-21', 1209.0, 4, 1, NOW(), FALSE);
INSERT INTO land (id, name, description, localizationX, localizationY, price, category_id, metaverse_id, created_At, deleted) VALUES (default, 'Wedding Party', 'Venha desbravar o metaverso. Inove realizando o seu casamento neste terreno.', '-125', '-67', 619.0, 1, 1, NOW(), FALSE);

--Land ID 1 - casamento
INSERT INTO images (id, title, url, land_id, created_At, deleted) VALUES (default, 'Espaço para eventos formais ideal para casamento', 'https://cdn.discordapp.com/attachments/981230317392240701/981236184682487888/parcel.png', 1, NOW(), FALSE);
INSERT INTO images (id, title, url, land_id, created_At, deleted) VALUES (default, 'Imagem 1 generica casamento', 'https://cdn.discordapp.com/attachments/981254612520693850/981256436485075034/casamento-1.jpeg', 1, NOW(), FALSE);
INSERT INTO images (id, title, url, land_id, created_At, deleted) VALUES (default, 'Imagem 2 generica casamento', 'https://cdn.discordapp.com/attachments/981254612520693850/981256462884016178/casamento-2.jpeg', 1, NOW(), FALSE);
INSERT INTO images (id, title, url, land_id, created_At, deleted) VALUES (default, 'Imagem 3 generica casamento', 'https://cdn.discordapp.com/attachments/981254612520693850/981256484769918976/casamento-3.jpeg', 1, NOW(), FALSE);
INSERT INTO images (id, title, url, land_id, created_At, deleted) VALUES (default, 'Imagem 4 generica casamento', 'https://cdn.discordapp.com/attachments/981254612520693850/981256499428999248/casamento-4.jpeg', 1, NOW(), FALSE);
INSERT INTO tb_land_attributes (land_id, attributes_id) VALUES (1, 5);
INSERT INTO tb_land_attributes (land_id, attributes_id) VALUES (1, 8);
INSERT INTO tb_land_attributes (land_id, attributes_id) VALUES (1, 1);

--Land ID 2 - festa e show
INSERT INTO images (id, title, url, land_id, created_At, deleted) VALUES (default, 'Terreno para festas e shows', 'https://cdn.discordapp.com/attachments/981230317392240701/981238453935144990/vegas-road-parcel.png', 2, NOW(), FALSE);
INSERT INTO images (id, title, url, land_id, created_At, deleted) VALUES (default, 'Imagem 1 generica festa e shows', 'https://cdn.discordapp.com/attachments/981257684303114270/981257826133508117/festa-e-show-1.jpeg', 2, NOW(), FALSE);
INSERT INTO images (id, title, url, land_id, created_At, deleted) VALUES (default, 'Imagem 2 generica festa e shows', 'https://cdn.discordapp.com/attachments/981257684303114270/981257846035464302/festa-e-show-2.jpeg', 2, NOW(), FALSE);
INSERT INTO images (id, title, url, land_id, created_At, deleted) VALUES (default, 'Imagem 3 generica festa e shows', 'https://cdn.discordapp.com/attachments/981257684303114270/981257869796179978/festa-e-show-3.jpeg', 2, NOW(), FALSE);
INSERT INTO images (id, title, url, land_id, created_At, deleted) VALUES (default, 'Imagem 4 generica festa e shows', 'https://cdn.discordapp.com/attachments/981257684303114270/981257884367216660/festa-e-show-4.jpeg', 2, NOW(), FALSE);
INSERT INTO images (id, title, url, land_id, created_At, deleted) VALUES (default, 'Imagem 5 generica festa e shows', 'https://cdn.discordapp.com/attachments/981257684303114270/981257898925649980/festa-e-show-5.jpeg', 2, NOW(), FALSE);
INSERT INTO tb_land_attributes (land_id, attributes_id) VALUES (2,6);
INSERT INTO tb_land_attributes (land_id, attributes_id) VALUES (2,10);
INSERT INTO tb_land_attributes (land_id, attributes_id) VALUES (2,3);

--Land ID 3 - divulgação
INSERT INTO images (id, title, url, land_id, created_At, deleted) VALUES (default, 'Divulgue já!', 'https://cdn.discordapp.com/attachments/981230317392240701/981240450671345684/vegas-city.png', 3, NOW(), FALSE);
INSERT INTO images (id, title, url, land_id, created_At, deleted) VALUES (default, 'Imagem 1 generica divulgação ', 'https://cdn.discordapp.com/attachments/981260096631885844/984078036381106236/Captura_de_Tela_2022-06-08_as_09.54.43.png', 3, NOW(), FALSE);
INSERT INTO images (id, title, url, land_id, created_At, deleted) VALUES (default, 'Imagem 2 generica divulgação', 'https://cdn.discordapp.com/attachments/981260096631885844/981260199312638012/divulgacao-geral-1.jpeg', 3, NOW(), FALSE);
INSERT INTO images (id, title, url, land_id, created_At, deleted) VALUES (default, 'Imagem 3 generica divulgação', 'https://cdn.discordapp.com/attachments/981260096631885844/981260227385098320/divulgacao-geral-2.jpeg', 3, NOW(), FALSE);
INSERT INTO images (id, title, url, land_id, created_At, deleted) VALUES (default, 'Imagem 4 generica divulgação', 'https://cdn.discordapp.com/attachments/981260096631885844/981260248818024538/divulgacao-geral-3.jpeg', 3, NOW(), FALSE);
INSERT INTO tb_land_attributes (land_id, attributes_id) VALUES (3, 7);
INSERT INTO tb_land_attributes (land_id, attributes_id) VALUES (3, 4);
INSERT INTO tb_land_attributes (land_id, attributes_id) VALUES (3, 2);

--Land ID 4 - divulgação
INSERT INTO images (id, title, url, land_id, created_At, deleted) VALUES (default, 'Amplo terreno para divulgar e promover a sua marca.', 'https://cdn.discordapp.com/attachments/981230317392240701/981242111015927899/on-road-opposite.png', 4, NOW(), FALSE);
INSERT INTO images (id, title, url, land_id, created_At, deleted) VALUES (default, 'Imagem 1 generica divulgação ', 'https://cdn.discordapp.com/attachments/981260096631885844/984078036381106236/Captura_de_Tela_2022-06-08_as_09.54.43.png', 4, NOW(), FALSE);
INSERT INTO images (id, title, url, land_id, created_At, deleted) VALUES (default, 'Imagem 2 generica divulgação', 'https://cdn.discordapp.com/attachments/981260096631885844/981260199312638012/divulgacao-geral-1.jpeg', 4, NOW(), FALSE);
INSERT INTO images (id, title, url, land_id, created_At, deleted) VALUES (default, 'Imagem 3 generica divulgação', 'https://cdn.discordapp.com/attachments/981260096631885844/981260227385098320/divulgacao-geral-2.jpeg', 4, NOW(), FALSE);
INSERT INTO images (id, title, url, land_id, created_At, deleted) VALUES (default, 'Imagem 4 generica divulgação', 'https://cdn.discordapp.com/attachments/981260096631885844/981260248818024538/divulgacao-geral-3.jpeg', 4, NOW(), FALSE);
INSERT INTO tb_land_attributes (land_id, attributes_id) VALUES (4, 2);
INSERT INTO tb_land_attributes (land_id, attributes_id) VALUES (4, 6);
INSERT INTO tb_land_attributes (land_id, attributes_id) VALUES (4, 1);

--Land ID 5 - lazer e recreação
INSERT INTO images (id, title, url, land_id, created_At, deleted) VALUES (default, 'Promova atividades culturais e recreativas neste terreno raro.', 'https://cdn.discordapp.com/attachments/981230317392240701/981244619318767616/Super-Rare-2x1.png', 5, NOW(), FALSE);
INSERT INTO images (id, title, url, land_id, created_At, deleted) VALUES (default, 'Imagem 1 generica lazer e recreação', 'https://cdn.discordapp.com/attachments/981261626302931054/981262171461795870/lazer-e-recreacao-1.jpeg', 5, NOW(), FALSE);
INSERT INTO images (id, title, url, land_id, created_At, deleted) VALUES (default, 'Imagem 2 generica lazer e recreação.', 'https://cdn.discordapp.com/attachments/981261626302931054/981262194903769088/lazer-e-recreacao-2.jpeg', 5, NOW(), FALSE);
INSERT INTO images (id, title, url, land_id, created_At, deleted) VALUES (default, 'Imagem 3 generica lazer e recreação', 'https://cdn.discordapp.com/attachments/981261626302931054/981262229125095512/lazer-e-recreacao-3.jpeg', 5, NOW(), FALSE);
INSERT INTO images (id, title, url, land_id, created_At, deleted) VALUES (default, 'Imagem 4 generica lazer e recreação', 'https://cdn.discordapp.com/attachments/981261626302931054/981262265317736508/lazer-e-recreacao-4.jpeg', 5, NOW(), FALSE);
INSERT INTO tb_land_attributes (land_id, attributes_id) VALUES (5, 6);
INSERT INTO tb_land_attributes (land_id, attributes_id) VALUES (5, 9);
INSERT INTO tb_land_attributes (land_id, attributes_id) VALUES (5, 4);

--Land ID 6 - lazer e recreação
INSERT INTO images (id, title, url, land_id, created_At, deleted) VALUES (default, 'Área projetada para recreação infantil. Muitos brinquedos.', 'https://cdn.discordapp.com/attachments/981230317392240701/981247723263127622/3-Away.png', 6, NOW(), FALSE);
INSERT INTO images (id, title, url, land_id, created_At, deleted) VALUES (default, 'Imagem 1 generica lazer e recreação', 'https://cdn.discordapp.com/attachments/981261626302931054/981262171461795870/lazer-e-recreacao-1.jpeg', 6, NOW(), FALSE);
INSERT INTO images (id, title, url, land_id, created_At, deleted) VALUES (default, 'Imagem 2 generica lazer e recreação.', 'https://cdn.discordapp.com/attachments/981261626302931054/981262194903769088/lazer-e-recreacao-2.jpeg', 6, NOW(), FALSE);
INSERT INTO images (id, title, url, land_id, created_At, deleted) VALUES (default, 'Imagem 3 generica lazer e recreação', 'https://cdn.discordapp.com/attachments/981261626302931054/981262229125095512/lazer-e-recreacao-3.jpeg', 6, NOW(), FALSE);
INSERT INTO images (id, title, url, land_id, created_At, deleted) VALUES (default, 'Imagem 4 generica lazer e recreação', 'https://cdn.discordapp.com/attachments/981261626302931054/981262265317736508/lazer-e-recreacao-4.jpeg', 6, NOW(), FALSE);
INSERT INTO tb_land_attributes (land_id, attributes_id) VALUES (6, 4);
INSERT INTO tb_land_attributes (land_id, attributes_id) VALUES (6, 10);
INSERT INTO tb_land_attributes (land_id, attributes_id) VALUES (6, 1);

--Land ID 7 - casamento
INSERT INTO images (id, title, url, land_id, created_At, deleted) VALUES (default, 'Ambiente próximo ao centro e aconchegante para cerimônias de casamento.', 'https://cdn.discordapp.com/attachments/981230317392240701/981249474900951060/Very-close-to-the-centre.png', 7, NOW(), FALSE);
INSERT INTO images (id, title, url, land_id, created_At, deleted) VALUES (default, 'Imagem 1 generica casamento', 'https://cdn.discordapp.com/attachments/981254612520693850/981256436485075034/casamento-1.jpeg', 7, NOW(), FALSE);
INSERT INTO images (id, title, url, land_id, created_At, deleted) VALUES (default, 'Imagem 2 generica casamento', 'https://cdn.discordapp.com/attachments/981254612520693850/981256462884016178/casamento-2.jpeg', 7, NOW(), FALSE);
INSERT INTO images (id, title, url, land_id, created_At, deleted) VALUES (default, 'Imagem 3 generica casamento', 'https://cdn.discordapp.com/attachments/981254612520693850/981256484769918976/casamento-3.jpeg', 7, NOW(), FALSE);
INSERT INTO images (id, title, url, land_id, created_At, deleted) VALUES (default, 'Imagem 4 generica casamento', 'https://cdn.discordapp.com/attachments/981254612520693850/981256499428999248/casamento-4.jpeg', 7, NOW(), FALSE);
INSERT INTO tb_land_attributes (land_id, attributes_id) VALUES (7, 5);
INSERT INTO tb_land_attributes (land_id, attributes_id) VALUES (7, 11);
INSERT INTO tb_land_attributes (land_id, attributes_id) VALUES (7, 1);

--Land ID 8 - divulgação
INSERT INTO images (id, title, url, land_id, created_At, deleted) VALUES (default, 'Raridade para a divulgação de marcas.', 'https://cdn.discordapp.com/attachments/981230317392240701/981250412290134046/rare.png', 8, NOW(), FALSE);
INSERT INTO images (id, title, url, land_id, created_At, deleted) VALUES (default, 'Imagem 1 generica divulgação ', 'https://cdn.discordapp.com/attachments/981260096631885844/984078036381106236/Captura_de_Tela_2022-06-08_as_09.54.43.png', 8, NOW(), FALSE);
INSERT INTO images (id, title, url, land_id, created_At, deleted) VALUES (default, 'Imagem 2 generica divulgação', 'https://cdn.discordapp.com/attachments/981260096631885844/981260199312638012/divulgacao-geral-1.jpeg', 8, NOW(), FALSE);
INSERT INTO images (id, title, url, land_id, created_At, deleted) VALUES (default, 'Imagem 3 generica divulgação', 'https://cdn.discordapp.com/attachments/981260096631885844/981260227385098320/divulgacao-geral-2.jpeg', 8, NOW(), FALSE);
INSERT INTO images (id, title, url, land_id, created_At, deleted) VALUES (default, 'Imagem 4 generica divulgação', 'https://cdn.discordapp.com/attachments/981260096631885844/981260248818024538/divulgacao-geral-3.jpeg', 8, NOW(), FALSE);
INSERT INTO tb_land_attributes (land_id, attributes_id) VALUES (8, 6);
INSERT INTO tb_land_attributes (land_id, attributes_id) VALUES (8, 8);
INSERT INTO tb_land_attributes (land_id, attributes_id) VALUES (8, 2);

--Land ID 9 - festa e show
INSERT INTO images (id, title, url, land_id, created_At, deleted) VALUES (default, 'Amplo espaço para a realização de festas e shows.', 'https://cdn.discordapp.com/attachments/981230317392240701/981252022617653398/3-parcel-state.png', 9, NOW(), FALSE);
INSERT INTO images (id, title, url, land_id, created_At, deleted) VALUES (default, 'Imagem 1 generica festa e shows', 'https://cdn.discordapp.com/attachments/981257684303114270/981257826133508117/festa-e-show-1.jpeg', 9, NOW(), FALSE);
INSERT INTO images (id, title, url, land_id, created_At, deleted) VALUES (default, 'Imagem 2 generica festa e shows', 'https://cdn.discordapp.com/attachments/981257684303114270/981257846035464302/festa-e-show-2.jpeg', 9, NOW(), FALSE);
INSERT INTO images (id, title, url, land_id, created_At, deleted) VALUES (default, 'Imagem 3 generica festa e shows', 'https://cdn.discordapp.com/attachments/981257684303114270/981257869796179978/festa-e-show-3.jpeg', 9, NOW(), FALSE);
INSERT INTO images (id, title, url, land_id, created_At, deleted) VALUES (default, 'Imagem 4 generica festa e shows', 'https://cdn.discordapp.com/attachments/981257684303114270/981257884367216660/festa-e-show-4.jpeg', 9, NOW(), FALSE);
INSERT INTO images (id, title, url, land_id, created_At, deleted) VALUES (default, 'Imagem 5 generica festa e shows', 'https://cdn.discordapp.com/attachments/981257684303114270/981257898925649980/festa-e-show-5.jpeg', 9, NOW(), FALSE);
INSERT INTO tb_land_attributes (land_id, attributes_id) VALUES (9, 9);
INSERT INTO tb_land_attributes (land_id, attributes_id) VALUES (9, 8);
INSERT INTO tb_land_attributes (land_id, attributes_id) VALUES (9, 10);

--Land ID 10 - divulgação
INSERT INTO images (id, title, url, land_id, created_At, deleted) VALUES (default, 'Ótima opção para investimento', 'https://cdn.discordapp.com/attachments/981881034658439259/981881229219627048/1.png', 10, NOW(), FALSE);
INSERT INTO images (id, title, url, land_id, created_At, deleted) VALUES (default, 'Imagem 1 generica divulgação ', 'https://cdn.discordapp.com/attachments/981260096631885844/984078036381106236/Captura_de_Tela_2022-06-08_as_09.54.43.png', 10, NOW(), FALSE);
INSERT INTO images (id, title, url, land_id, created_At, deleted) VALUES (default, 'Imagem 2 generica divulgação', 'https://cdn.discordapp.com/attachments/981260096631885844/981260199312638012/divulgacao-geral-1.jpeg', 10, NOW(), FALSE);
INSERT INTO images (id, title, url, land_id, created_At, deleted) VALUES (default, 'Imagem 3 generica divulgação', 'https://cdn.discordapp.com/attachments/981260096631885844/981260227385098320/divulgacao-geral-2.jpeg', 10, NOW(), FALSE);
INSERT INTO images (id, title, url, land_id, created_At, deleted) VALUES (default, 'Imagem 4 generica divulgação', 'https://cdn.discordapp.com/attachments/981260096631885844/981260248818024538/divulgacao-geral-3.jpeg', 10, NOW(), FALSE);
INSERT INTO tb_land_attributes (land_id, attributes_id) VALUES (10, 1);
INSERT INTO tb_land_attributes (land_id, attributes_id) VALUES (10, 2);
INSERT INTO tb_land_attributes (land_id, attributes_id) VALUES (10, 7);

--Land ID 11 - casamento
INSERT INTO images (id, title, url, land_id, created_At, deleted) VALUES (default, 'Ambiente para casamento', 'https://cdn.discordapp.com/attachments/981881034658439259/981883088634249256/2.png', 11, NOW(), FALSE);
INSERT INTO images (id, title, url, land_id, created_At, deleted) VALUES (default, 'Imagem 1 generica casamento', 'https://cdn.discordapp.com/attachments/981254612520693850/981256436485075034/casamento-1.jpeg', 11, NOW(), FALSE);
INSERT INTO images (id, title, url, land_id, created_At, deleted) VALUES (default, 'Imagem 2 generica casamento', 'https://cdn.discordapp.com/attachments/981254612520693850/981256462884016178/casamento-2.jpeg', 11, NOW(), FALSE);
INSERT INTO images (id, title, url, land_id, created_At, deleted) VALUES (default, 'Imagem 3 generica casamento', 'https://cdn.discordapp.com/attachments/981254612520693850/981256484769918976/casamento-3.jpeg', 11, NOW(), FALSE);
INSERT INTO images (id, title, url, land_id, created_At, deleted) VALUES (default, 'Imagem 4 generica casamento', 'https://cdn.discordapp.com/attachments/981254612520693850/981256499428999248/casamento-4.jpeg', 11, NOW(), FALSE);
INSERT INTO tb_land_attributes (land_id, attributes_id) VALUES (11, 2);
INSERT INTO tb_land_attributes (land_id, attributes_id) VALUES (11, 11);
INSERT INTO tb_land_attributes (land_id, attributes_id) VALUES (11, 1);

--Land ID 12 - lazer e recreação
INSERT INTO images (id, title, url, land_id, created_At, deleted) VALUES (default, 'Atividades esportivas', 'https://cdn.discordapp.com/attachments/981881034658439259/981883385070878751/3.png', 12, NOW(), FALSE);
INSERT INTO images (id, title, url, land_id, created_At, deleted) VALUES (default, 'Imagem 1 generica lazer e recreação', 'https://cdn.discordapp.com/attachments/981261626302931054/981262171461795870/lazer-e-recreacao-1.jpeg', 12, NOW(), FALSE);
INSERT INTO images (id, title, url, land_id, created_At, deleted) VALUES (default, 'Imagem 2 generica lazer e recreação.', 'https://cdn.discordapp.com/attachments/981261626302931054/981262194903769088/lazer-e-recreacao-2.jpeg', 12, NOW(), FALSE);
INSERT INTO images (id, title, url, land_id, created_At, deleted) VALUES (default, 'Imagem 3 generica lazer e recreação', 'https://cdn.discordapp.com/attachments/981261626302931054/981262229125095512/lazer-e-recreacao-3.jpeg', 12, NOW(), FALSE);
INSERT INTO images (id, title, url, land_id, created_At, deleted) VALUES (default, 'Imagem 4 generica lazer e recreação', 'https://cdn.discordapp.com/attachments/981261626302931054/981262265317736508/lazer-e-recreacao-4.jpeg', 12, NOW(), FALSE);
INSERT INTO tb_land_attributes (land_id, attributes_id) VALUES (12, 3);
INSERT INTO tb_land_attributes (land_id, attributes_id) VALUES (12, 4);
INSERT INTO tb_land_attributes (land_id, attributes_id) VALUES (12, 11);

--Land ID 13 - festa e show
INSERT INTO images (id, title, url, land_id, created_At, deleted) VALUES (default, 'Oportunidade de investimento', 'https://cdn.discordapp.com/attachments/981881034658439259/981910794973372437/4.png', 13, NOW(), FALSE);
INSERT INTO images (id, title, url, land_id, created_At, deleted) VALUES (default, 'Imagem 1 generica festa e shows', 'https://cdn.discordapp.com/attachments/981257684303114270/981257826133508117/festa-e-show-1.jpeg', 13, NOW(), FALSE);
INSERT INTO images (id, title, url, land_id, created_At, deleted) VALUES (default, 'Imagem 2 generica festa e shows', 'https://cdn.discordapp.com/attachments/981257684303114270/981257846035464302/festa-e-show-2.jpeg', 13, NOW(), FALSE);
INSERT INTO images (id, title, url, land_id, created_At, deleted) VALUES (default, 'Imagem 3 generica festa e shows', 'https://cdn.discordapp.com/attachments/981257684303114270/981257869796179978/festa-e-show-3.jpeg', 13, NOW(), FALSE);
INSERT INTO images (id, title, url, land_id, created_At, deleted) VALUES (default, 'Imagem 4 generica festa e shows', 'https://cdn.discordapp.com/attachments/981257684303114270/981257884367216660/festa-e-show-4.jpeg', 13, NOW(), FALSE);
INSERT INTO images (id, title, url, land_id, created_At, deleted) VALUES (default, 'Imagem 5 generica festa e shows', 'https://cdn.discordapp.com/attachments/981257684303114270/981257898925649980/festa-e-show-5.jpeg', 13, NOW(), FALSE);
INSERT INTO tb_land_attributes (land_id, attributes_id) VALUES (13, 9);
INSERT INTO tb_land_attributes (land_id, attributes_id) VALUES (13, 11);
INSERT INTO tb_land_attributes (land_id, attributes_id) VALUES (13, 2);

--Land ID 14 - festa e show
INSERT INTO images (id, title, url, land_id, created_At, deleted) VALUES (default, 'Amplo terreno para festas e grandes eventos', 'https://cdn.discordapp.com/attachments/981881034658439259/981911826361114624/5.png', 14, NOW(), FALSE);
INSERT INTO images (id, title, url, land_id, created_At, deleted) VALUES (default, 'Imagem 1 generica festa e shows', 'https://cdn.discordapp.com/attachments/981257684303114270/981257826133508117/festa-e-show-1.jpeg', 14, NOW(), FALSE);
INSERT INTO images (id, title, url, land_id, created_At, deleted) VALUES (default, 'Imagem 2 generica festa e shows', 'https://cdn.discordapp.com/attachments/981257684303114270/981257846035464302/festa-e-show-2.jpeg', 14, NOW(), FALSE);
INSERT INTO images (id, title, url, land_id, created_At, deleted) VALUES (default, 'Imagem 3 generica festa e shows', 'https://cdn.discordapp.com/attachments/981257684303114270/981257869796179978/festa-e-show-3.jpeg', 14, NOW(), FALSE);
INSERT INTO images (id, title, url, land_id, created_At, deleted) VALUES (default, 'Imagem 4 generica festa e shows', 'https://cdn.discordapp.com/attachments/981257684303114270/981257884367216660/festa-e-show-4.jpeg', 14, NOW(), FALSE);
INSERT INTO images (id, title, url, land_id, created_At, deleted) VALUES (default, 'Imagem 5 generica festa e shows', 'https://cdn.discordapp.com/attachments/981257684303114270/981257898925649980/festa-e-show-5.jpeg', 14, NOW(), FALSE);
INSERT INTO tb_land_attributes (land_id, attributes_id) VALUES (14, 1);
INSERT INTO tb_land_attributes (land_id, attributes_id) VALUES (14, 10);
INSERT INTO tb_land_attributes (land_id, attributes_id) VALUES (14, 5);

--Land ID 15 - divulgação
INSERT INTO images (id, title, url, land_id, created_At, deleted) VALUES (default, 'Badalado terreno para divulgar seu negócio.', 'https://cdn.discordapp.com/attachments/981881034658439259/981972359143632896/unknown.png', 15, NOW(), FALSE);
INSERT INTO images (id, title, url, land_id, created_At, deleted) VALUES (default, 'Imagem 1 generica divulgação ', 'https://cdn.discordapp.com/attachments/981260096631885844/984078036381106236/Captura_de_Tela_2022-06-08_as_09.54.43.png', 15, NOW(), FALSE);
INSERT INTO images (id, title, url, land_id, created_At, deleted) VALUES (default, 'Imagem 2 generica divulgação', 'https://cdn.discordapp.com/attachments/981260096631885844/981260199312638012/divulgacao-geral-1.jpeg', 15, NOW(), FALSE);
INSERT INTO images (id, title, url, land_id, created_At, deleted) VALUES (default, 'Imagem 3 generica divulgação', 'https://cdn.discordapp.com/attachments/981260096631885844/981260227385098320/divulgacao-geral-2.jpeg', 15, NOW(), FALSE);
INSERT INTO images (id, title, url, land_id, created_At, deleted) VALUES (default, 'Imagem 4 generica divulgação', 'https://cdn.discordapp.com/attachments/981260096631885844/981260248818024538/divulgacao-geral-3.jpeg', 15, NOW(), FALSE);
INSERT INTO tb_land_attributes (land_id, attributes_id) VALUES (15, 7);
INSERT INTO tb_land_attributes (land_id, attributes_id) VALUES (15, 2);
INSERT INTO tb_land_attributes (land_id, attributes_id) VALUES (15, 11);

--Land ID 16 - casamento
INSERT INTO images (id, title, url, land_id, created_At, deleted) VALUES (default, 'Seu casamento é aqui', 'https://cdn.discordapp.com/attachments/981881034658439259/982237787468230707/unknown.png', 16, NOW(), FALSE);
INSERT INTO images (id, title, url, land_id, created_At, deleted) VALUES (default, 'Imagem 1 generica casamento', 'https://cdn.discordapp.com/attachments/981254612520693850/981256436485075034/casamento-1.jpeg', 16, NOW(), FALSE);
INSERT INTO images (id, title, url, land_id, created_At, deleted) VALUES (default, 'Imagem 2 generica casamento', 'https://cdn.discordapp.com/attachments/981254612520693850/981256462884016178/casamento-2.jpeg', 16, NOW(), FALSE);
INSERT INTO images (id, title, url, land_id, created_At, deleted) VALUES (default, 'Imagem 3 generica casamento', 'https://cdn.discordapp.com/attachments/981254612520693850/981256484769918976/casamento-3.jpeg', 16, NOW(), FALSE);
INSERT INTO images (id, title, url, land_id, created_At, deleted) VALUES (default, 'Imagem 4 generica casamento', 'https://cdn.discordapp.com/attachments/981254612520693850/981256499428999248/casamento-4.jpeg', 16, NOW(), FALSE);
INSERT INTO tb_land_attributes (land_id, attributes_id) VALUES (16, 1);
INSERT INTO tb_land_attributes (land_id, attributes_id) VALUES (16, 5);
INSERT INTO tb_land_attributes (land_id, attributes_id) VALUES (16, 7);

--Land ID 17 - lazer e recreação
INSERT INTO images (id, title, url, land_id, created_At, deleted) VALUES (default, 'Várias atividades em um único só lugar', 'https://cdn.discordapp.com/attachments/981881034658439259/982239862663028746/unknown.png', 17, NOW(), FALSE);
INSERT INTO images (id, title, url, land_id, created_At, deleted) VALUES (default, 'Imagem 1 generica lazer e recreação', 'https://cdn.discordapp.com/attachments/981261626302931054/981262171461795870/lazer-e-recreacao-1.jpeg', 17, NOW(), FALSE);
INSERT INTO images (id, title, url, land_id, created_At, deleted) VALUES (default, 'Imagem 2 generica lazer e recreação.', 'https://cdn.discordapp.com/attachments/981261626302931054/981262194903769088/lazer-e-recreacao-2.jpeg', 17, NOW(), FALSE);
INSERT INTO images (id, title, url, land_id, created_At, deleted) VALUES (default, 'Imagem 3 generica lazer e recreação', 'https://cdn.discordapp.com/attachments/981261626302931054/981262229125095512/lazer-e-recreacao-3.jpeg', 17, NOW(), FALSE);
INSERT INTO images (id, title, url, land_id, created_At, deleted) VALUES (default, 'Imagem 4 generica lazer e recreação', 'https://cdn.discordapp.com/attachments/981261626302931054/981262265317736508/lazer-e-recreacao-4.jpeg', 17, NOW(), FALSE);
INSERT INTO tb_land_attributes (land_id, attributes_id) VALUES (17, 10);
INSERT INTO tb_land_attributes (land_id, attributes_id) VALUES (17, 3);
INSERT INTO tb_land_attributes (land_id, attributes_id) VALUES (17, 9);

--Land ID 18 - festa e show
INSERT INTO images (id, title, url, land_id, created_At, deleted) VALUES (default, 'Faça a melhor festa no metaverso', 'https://cdn.discordapp.com/attachments/981881034658439259/982243124061540412/unknown.png', 18, NOW(), FALSE);
INSERT INTO images (id, title, url, land_id, created_At, deleted) VALUES (default, 'Imagem 1 generica festa e shows', 'https://cdn.discordapp.com/attachments/981257684303114270/981257826133508117/festa-e-show-1.jpeg', 18, NOW(), FALSE);
INSERT INTO images (id, title, url, land_id, created_At, deleted) VALUES (default, 'Imagem 2 generica festa e shows', 'https://cdn.discordapp.com/attachments/981257684303114270/981257846035464302/festa-e-show-2.jpeg', 18, NOW(), FALSE);
INSERT INTO images (id, title, url, land_id, created_At, deleted) VALUES (default, 'Imagem 3 generica festa e shows', 'https://cdn.discordapp.com/attachments/981257684303114270/981257869796179978/festa-e-show-3.jpeg', 18, NOW(), FALSE);
INSERT INTO images (id, title, url, land_id, created_At, deleted) VALUES (default, 'Imagem 4 generica festa e shows', 'https://cdn.discordapp.com/attachments/981257684303114270/981257884367216660/festa-e-show-4.jpeg', 18, NOW(), FALSE);
INSERT INTO images (id, title, url, land_id, created_At, deleted) VALUES (default, 'Imagem 5 generica festa e shows', 'https://cdn.discordapp.com/attachments/981257684303114270/981257898925649980/festa-e-show-5.jpeg', 18, NOW(), FALSE);
INSERT INTO tb_land_attributes (land_id, attributes_id) VALUES (18, 10);
INSERT INTO tb_land_attributes (land_id, attributes_id) VALUES (18, 11);
INSERT INTO tb_land_attributes (land_id, attributes_id) VALUES (18, 6);

--Land ID 19 - lazer e recreação
INSERT INTO images (id, title, url, land_id, created_At, deleted) VALUES (default, 'Encontre a diversão perfeita', 'https://cdn.discordapp.com/attachments/981230317392240701/981244619318767616/Super-Rare-2x1.png', 19, NOW(), FALSE);
INSERT INTO images (id, title, url, land_id, created_At, deleted) VALUES (default, 'Imagem 1 generica lazer e recreação', 'https://cdn.discordapp.com/attachments/981261626302931054/981262171461795870/lazer-e-recreacao-1.jpeg', 19, NOW(), FALSE);
INSERT INTO images (id, title, url, land_id, created_At, deleted) VALUES (default, 'Imagem 2 generica lazer e recreação.', 'https://cdn.discordapp.com/attachments/981261626302931054/981262194903769088/lazer-e-recreacao-2.jpeg', 19, NOW(), FALSE);
INSERT INTO images (id, title, url, land_id, created_At, deleted) VALUES (default, 'Imagem 3 generica lazer e recreação', 'https://cdn.discordapp.com/attachments/981261626302931054/981262229125095512/lazer-e-recreacao-3.jpeg', 19, NOW(), FALSE);
INSERT INTO images (id, title, url, land_id, created_At, deleted) VALUES (default, 'Imagem 4 generica lazer e recreação', 'https://cdn.discordapp.com/attachments/981261626302931054/981262265317736508/lazer-e-recreacao-4.jpeg', 19, NOW(), FALSE);
INSERT INTO tb_land_attributes (land_id, attributes_id) VALUES (19, 1);
INSERT INTO tb_land_attributes (land_id, attributes_id) VALUES (19, 4);
INSERT INTO tb_land_attributes (land_id, attributes_id) VALUES (19, 7);

--Land ID 20 - casamento
INSERT INTO images (id, title, url, land_id, created_At, deleted) VALUES (default, 'Estrutura projetada e pensada para realizar casamentos', 'https://cdn.discordapp.com/attachments/981881034658439259/982244141868154930/unknown.png', 20, NOW(), FALSE);
INSERT INTO images (id, title, url, land_id, created_At, deleted) VALUES (default, 'Imagem 1 generica casamento', 'https://cdn.discordapp.com/attachments/981254612520693850/981256436485075034/casamento-1.jpeg', 20, NOW(), FALSE);
INSERT INTO images (id, title, url, land_id, created_At, deleted) VALUES (default, 'Imagem 2 generica casamento', 'https://cdn.discordapp.com/attachments/981254612520693850/981256462884016178/casamento-2.jpeg', 20, NOW(), FALSE);
INSERT INTO images (id, title, url, land_id, created_At, deleted) VALUES (default, 'Imagem 3 generica casamento', 'https://cdn.discordapp.com/attachments/981254612520693850/981256484769918976/casamento-3.jpeg', 20, NOW(), FALSE);
INSERT INTO images (id, title, url, land_id, created_At, deleted) VALUES (default, 'Imagem 4 generica casamento', 'https://cdn.discordapp.com/attachments/981254612520693850/981256499428999248/casamento-4.jpeg', 20, NOW(), FALSE);
INSERT INTO tb_land_attributes (land_id, attributes_id) VALUES (20, 5);
INSERT INTO tb_land_attributes (land_id, attributes_id) VALUES (20, 10);
INSERT INTO tb_land_attributes (land_id, attributes_id) VALUES (20, 6);

--Land ID 21 - festa e show
INSERT INTO images (id, title, url, land_id, created_At, deleted) VALUES (default, 'Parcel', 'https://cdn.discordapp.com/attachments/981230317392240701/984126650738430052/unknown.png', 21, NOW(), FALSE);
INSERT INTO images (id, title, url, land_id, created_At, deleted) VALUES (default, 'Imagem 1 generica festa e shows', 'https://cdn.discordapp.com/attachments/981257684303114270/981257826133508117/festa-e-show-1.jpeg', 21, NOW(), FALSE);
INSERT INTO images (id, title, url, land_id, created_At, deleted) VALUES (default, 'Imagem 2 generica festa e shows', 'https://cdn.discordapp.com/attachments/981257684303114270/981257846035464302/festa-e-show-2.jpeg', 21, NOW(), FALSE);
INSERT INTO images (id, title, url, land_id, created_At, deleted) VALUES (default, 'Imagem 3 generica festa e shows', 'https://cdn.discordapp.com/attachments/981257684303114270/981257869796179978/festa-e-show-3.jpeg', 21, NOW(), FALSE);
INSERT INTO images (id, title, url, land_id, created_At, deleted) VALUES (default, 'Imagem 4 generica festa e shows', 'https://cdn.discordapp.com/attachments/981257684303114270/981257884367216660/festa-e-show-4.jpeg', 21, NOW(), FALSE);
INSERT INTO images (id, title, url, land_id, created_At, deleted) VALUES (default, 'Imagem 5 generica festa e shows', 'https://cdn.discordapp.com/attachments/981257684303114270/981257898925649980/festa-e-show-5.jpeg', 21, NOW(), FALSE);
INSERT INTO tb_land_attributes (land_id, attributes_id) VALUES (21, 1);
INSERT INTO tb_land_attributes (land_id, attributes_id) VALUES (21, 3);
INSERT INTO tb_land_attributes (land_id, attributes_id) VALUES (21, 11);

--Land ID 22 - lazer e recreação
INSERT INTO images (id, title, url, land_id, created_At, deleted) VALUES (default, 'Genesis Park', 'https://cdn.discordapp.com/attachments/981230317392240701/984128983320911982/unknown.pngg', 22, NOW(), FALSE);
INSERT INTO images (id, title, url, land_id, created_At, deleted) VALUES (default, 'Imagem 1 generica lazer e recreação', 'https://cdn.discordapp.com/attachments/981261626302931054/981262171461795870/lazer-e-recreacao-1.jpeg', 22, NOW(), FALSE);
INSERT INTO images (id, title, url, land_id, created_At, deleted) VALUES (default, 'Imagem 2 generica lazer e recreação.', 'https://cdn.discordapp.com/attachments/981261626302931054/981262194903769088/lazer-e-recreacao-2.jpeg', 22, NOW(), FALSE);
INSERT INTO images (id, title, url, land_id, created_At, deleted) VALUES (default, 'Imagem 3 generica lazer e recreação', 'https://cdn.discordapp.com/attachments/981261626302931054/981262229125095512/lazer-e-recreacao-3.jpeg', 22, NOW(), FALSE);
INSERT INTO images (id, title, url, land_id, created_At, deleted) VALUES (default, 'Imagem 4 generica lazer e recreação', 'https://cdn.discordapp.com/attachments/981261626302931054/981262265317736508/lazer-e-recreacao-4.jpeg', 22, NOW(), FALSE);
INSERT INTO tb_land_attributes (land_id, attributes_id) VALUES (22, 9);
INSERT INTO tb_land_attributes (land_id, attributes_id) VALUES (22, 4);
INSERT INTO tb_land_attributes (land_id, attributes_id) VALUES (22, 7);

--Land ID 23 - divulgação
INSERT INTO images (id, title, url, land_id, created_At, deleted) VALUES (default, 'Estate near Fashion', 'https://cdn.discordapp.com/attachments/981230317392240701/984131001049579571/unknown.png', 23, NOW(), FALSE);
INSERT INTO images (id, title, url, land_id, created_At, deleted) VALUES (default, 'Imagem 1 generica divulgação ', 'https://cdn.discordapp.com/attachments/981260096631885844/984078036381106236/Captura_de_Tela_2022-06-08_as_09.54.43.png', 23, NOW(), FALSE);
INSERT INTO images (id, title, url, land_id, created_At, deleted) VALUES (default, 'Imagem 2 generica divulgação', 'https://cdn.discordapp.com/attachments/981260096631885844/981260199312638012/divulgacao-geral-1.jpeg', 23, NOW(), FALSE);
INSERT INTO images (id, title, url, land_id, created_At, deleted) VALUES (default, 'Imagem 3 generica divulgação', 'https://cdn.discordapp.com/attachments/981260096631885844/981260227385098320/divulgacao-geral-2.jpeg', 23, NOW(), FALSE);
INSERT INTO images (id, title, url, land_id, created_At, deleted) VALUES (default, 'Imagem 4 generica divulgação', 'https://cdn.discordapp.com/attachments/981260096631885844/981260248818024538/divulgacao-geral-3.jpeg', 23, NOW(), FALSE);
INSERT INTO tb_land_attributes (land_id, attributes_id) VALUES (23, 11);
INSERT INTO tb_land_attributes (land_id, attributes_id) VALUES (23, 2);
INSERT INTO tb_land_attributes (land_id, attributes_id) VALUES (23, 8);

--Land ID 24 - festa e show
INSERT INTO images (id, title, url, land_id, created_At, deleted) VALUES (default, 'Arena Shows', 'https://cdn.discordapp.com/attachments/981230317392240701/984132838246977616/unknown.png', 24, NOW(), FALSE);
INSERT INTO images (id, title, url, land_id, created_At, deleted) VALUES (default, 'Imagem 1 generica festa e shows', 'https://cdn.discordapp.com/attachments/981257684303114270/981257826133508117/festa-e-show-1.jpeg', 24, NOW(), FALSE);
INSERT INTO images (id, title, url, land_id, created_At, deleted) VALUES (default, 'Imagem 2 generica festa e shows', 'https://cdn.discordapp.com/attachments/981257684303114270/981257846035464302/festa-e-show-2.jpeg', 24, NOW(), FALSE);
INSERT INTO images (id, title, url, land_id, created_At, deleted) VALUES (default, 'Imagem 3 generica festa e shows', 'https://cdn.discordapp.com/attachments/981257684303114270/981257869796179978/festa-e-show-3.jpeg', 24, NOW(), FALSE);
INSERT INTO images (id, title, url, land_id, created_At, deleted) VALUES (default, 'Imagem 4 generica festa e shows', 'https://cdn.discordapp.com/attachments/981257684303114270/981257884367216660/festa-e-show-4.jpeg', 24, NOW(), FALSE);
INSERT INTO images (id, title, url, land_id, created_At, deleted) VALUES (default, 'Imagem 5 generica festa e shows', 'https://cdn.discordapp.com/attachments/981257684303114270/981257898925649980/festa-e-show-5.jpeg', 24, NOW(), FALSE);
INSERT INTO tb_land_attributes (land_id, attributes_id) VALUES (24, 6);
INSERT INTO tb_land_attributes (land_id, attributes_id) VALUES (24, 10);
INSERT INTO tb_land_attributes (land_id, attributes_id) VALUES (24, 1);

--Land ID 25 - lazer e recreação
INSERT INTO images (id, title, url, land_id, created_At, deleted) VALUES (default, 'Street Land', 'https://cdn.discordapp.com/attachments/981230317392240701/984133857492234250/unknown.png', 25, NOW(), FALSE);
INSERT INTO images (id, title, url, land_id, created_At, deleted) VALUES (default, 'Imagem 1 generica lazer e recreação', 'https://cdn.discordapp.com/attachments/981261626302931054/981262171461795870/lazer-e-recreacao-1.jpeg', 25, NOW(), FALSE);
INSERT INTO images (id, title, url, land_id, created_At, deleted) VALUES (default, 'Imagem 2 generica lazer e recreação.', 'https://cdn.discordapp.com/attachments/981261626302931054/981262194903769088/lazer-e-recreacao-2.jpeg', 25, NOW(), FALSE);
INSERT INTO images (id, title, url, land_id, created_At, deleted) VALUES (default, 'Imagem 3 generica lazer e recreação', 'https://cdn.discordapp.com/attachments/981261626302931054/981262229125095512/lazer-e-recreacao-3.jpeg', 25, NOW(), FALSE);
INSERT INTO images (id, title, url, land_id, created_At, deleted) VALUES (default, 'Imagem 4 generica lazer e recreação', 'https://cdn.discordapp.com/attachments/981261626302931054/981262265317736508/lazer-e-recreacao-4.jpeg', 25, NOW(), FALSE);
INSERT INTO tb_land_attributes (land_id, attributes_id) VALUES (25, 4);
INSERT INTO tb_land_attributes (land_id, attributes_id) VALUES (25, 8);
INSERT INTO tb_land_attributes (land_id, attributes_id) VALUES (25, 10);

--Land ID 26 - casamento
INSERT INTO images (id, title, url, land_id, created_At, deleted) VALUES (default, 'Wedding Party', 'https://cdn.discordapp.com/attachments/981230317392240701/984135324856905728/unknown.png', 26, NOW(), FALSE);
INSERT INTO images (id, title, url, land_id, created_At, deleted) VALUES (default, 'Imagem 1 generica casamento', 'https://cdn.discordapp.com/attachments/981254612520693850/981256436485075034/casamento-1.jpeg', 26, NOW(), FALSE);
INSERT INTO images (id, title, url, land_id, created_At, deleted) VALUES (default, 'Imagem 2 generica casamento', 'https://cdn.discordapp.com/attachments/981254612520693850/981256462884016178/casamento-2.jpeg', 26, NOW(), FALSE);
INSERT INTO images (id, title, url, land_id, created_At, deleted) VALUES (default, 'Imagem 3 generica casamento', 'https://cdn.discordapp.com/attachments/981254612520693850/981256484769918976/casamento-3.jpeg', 26, NOW(), FALSE);
INSERT INTO images (id, title, url, land_id, created_At, deleted) VALUES (default, 'Imagem 4 generica casamento', 'https://cdn.discordapp.com/attachments/981254612520693850/981256499428999248/casamento-4.jpeg', 26, NOW(), FALSE);
INSERT INTO tb_land_attributes (land_id, attributes_id) VALUES (26, 5);
INSERT INTO tb_land_attributes (land_id, attributes_id) VALUES (26, 10);
INSERT INTO tb_land_attributes (land_id, attributes_id) VALUES (26, 3);

-- Role
INSERT INTO role (id, name, created_At, deleted) VALUES (default, 'ROLE_ADMIN', NOW(), FALSE);
INSERT INTO role (id, name, created_At, deleted) VALUES (default, 'ROLE_CLIENT', NOW(), FALSE);

-- User tb_user
INSERT INTO tb_user (id, name, last_name, email, password, created_At, deleted) VALUES (default, 'Teodoro', 'Alves', 'teodoro@gmail.com', '$2a$10$chi5SYpmIHDWpjF23zYaUu6KH7lwxG34jIKu0HvEeKt0dF/1dbxDa',NOW(), FALSE);
INSERT INTO tb_user (id, name, last_name, email, password, created_At, deleted) VALUES (default, 'Alice', 'Silveira', 'alice@gmail.com', '$2a$10$chi5SYpmIHDWpjF23zYaUu6KH7lwxG34jIKu0HvEeKt0dF/1dbxDa',  NOW(), FALSE);
INSERT INTO tb_user (id, name, last_name, email, password, created_At, deleted) VALUES (default, 'Berenice', 'Siqueira', 'b@gmail.com', '$2a$10$chi5SYpmIHDWpjF23zYaUu6KH7lwxG34jIKu0HvEeKt0dF/1dbxDa',  NOW(), FALSE);
INSERT INTO tb_user (id, name, last_name, email, password, created_At, deleted) VALUES (default, 'Camila', 'Antunes', 'c@gmail.com', '$2a$10$chi5SYpmIHDWpjF23zYaUu6KH7lwxG34jIKu0HvEeKt0dF/1dbxDa',  NOW(), FALSE);
INSERT INTO tb_user (id, name, last_name, email, password, created_At, deleted) VALUES (default, 'Andre', 'Padilha', 'padilha@gmail.com', '$2a$10$chi5SYpmIHDWpjF23zYaUu6KH7lwxG34jIKu0HvEeKt0dF/1dbxDa',NOW(), FALSE);
INSERT INTO tb_user (id, name, last_name, email, password, created_At, deleted) VALUES (default, 'Marcia', 'Yano', 'yurimarcia@yahoo.com.br', '$2a$10$chi5SYpmIHDWpjF23zYaUu6KH7lwxG34jIKu0HvEeKt0dF/1dbxDa',NOW(), FALSE);
INSERT INTO tb_user (id, name, last_name, email, password, created_At, deleted) VALUES (default, 'Renan', 'Joaquim', 'renan.aj94@gmail.com', '$2a$10$chi5SYpmIHDWpjF23zYaUu6KH7lwxG34jIKu0HvEeKt0dF/1dbxDa',NOW(), FALSE);
INSERT INTO tb_user (id, name, last_name, email, password, created_At, deleted) VALUES (default, 'Jehan', 'Ribeiro', 'jehanl.ribeiro@gmail.com', '$2a$10$chi5SYpmIHDWpjF23zYaUu6KH7lwxG34jIKu0HvEeKt0dF/1dbxDa',NOW(), FALSE);
INSERT INTO tb_user (id, name, last_name, email, password, created_At, deleted) VALUES (default, 'Matheus', 'Braga', 'matheusbragaprofissional@gmail.com', '$2a$10$chi5SYpmIHDWpjF23zYaUu6KH7lwxG34jIKu0HvEeKt0dF/1dbxDa',NOW(), FALSE);
INSERT INTO tb_user (id, name, last_name, email, password, created_At, deleted) VALUES (default, 'Vanessa', 'Matos', 'vanessammaganhoto@gmail.com', '$2a$10$chi5SYpmIHDWpjF23zYaUu6KH7lwxG34jIKu0HvEeKt0dF/1dbxDa',NOW(), FALSE);

-- tb_user_role
INSERT INTO tb_user_role (user_id, role_id) VALUES (1, 2);
INSERT INTO tb_user_role (user_id, role_id) VALUES (2, 2);
INSERT INTO tb_user_role (user_id, role_id) VALUES (3, 2);
INSERT INTO tb_user_role (user_id, role_id) VALUES (4, 2);
--Usuários do grupo. Todos são ADMIN e CLIENT
INSERT INTO tb_user_role (user_id, role_id) VALUES (5, 1); -- André
INSERT INTO tb_user_role (user_id, role_id) VALUES (5, 2); -- André
INSERT INTO tb_user_role (user_id, role_id) VALUES (6, 1); -- Marcia
INSERT INTO tb_user_role (user_id, role_id) VALUES (6, 2); -- Marcia
INSERT INTO tb_user_role (user_id, role_id) VALUES (7, 1); -- Renan
INSERT INTO tb_user_role (user_id, role_id) VALUES (7, 2); -- Renan
INSERT INTO tb_user_role (user_id, role_id) VALUES (8, 1); -- Jehan
INSERT INTO tb_user_role (user_id, role_id) VALUES (8, 2); -- Jehan
INSERT INTO tb_user_role (user_id, role_id) VALUES (9, 1); -- Matheus
INSERT INTO tb_user_role (user_id, role_id) VALUES (9, 2); -- Matheus
INSERT INTO tb_user_role (user_id, role_id) VALUES (10, 1); -- Vanessa
INSERT INTO tb_user_role (user_id, role_id) VALUES (10, 2); -- Vanessa

-- Reservation
INSERT INTO reservation (id, date_initial, date_final, user_id, land_id, created_At, deleted) VALUES  (default, '2022-05-05', '2022-05-10', 1, 1, NOW(), FALSE);
INSERT INTO reservation (id, date_initial, date_final, user_id, land_id, created_At, deleted) VALUES  (default, '2022-05-06', '2022-05-11', 1, 20, NOW(), FALSE);
INSERT INTO reservation (id, date_initial, date_final, user_id, land_id, created_At, deleted) VALUES  (default, '2022-05-07', '2022-05-12', 2, 5, NOW(), FALSE);
INSERT INTO reservation (id, date_initial, date_final, user_id, land_id, created_At, deleted) VALUES  (default, '2022-05-08', '2022-05-13', 3, 16, NOW(), FALSE);
INSERT INTO reservation (id, date_initial, date_final, user_id, land_id, created_At, deleted) VALUES  (default, '2022-05-09', '2022-05-14', 3, 4, NOW(), FALSE);
INSERT INTO reservation (id, date_initial, date_final, user_id, land_id, created_At, deleted) VALUES  (default, '2022-05-10', '2022-05-15', 4, 1, NOW(), FALSE);
INSERT INTO reservation (id, date_initial, date_final, user_id, land_id, created_At, deleted) VALUES  (default, '2022-05-11', '2022-05-16', 4, 1, NOW(), FALSE);



