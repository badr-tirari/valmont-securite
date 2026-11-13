-- Échantillon fourni par le sujet (données fictives) — état AVANT migration.
SET NAMES utf8mb4;
CREATE DATABASE IF NOT EXISTS valmont CHARACTER SET utf8mb4;
USE valmont;

CREATE TABLE patients (
    id             INT PRIMARY KEY,
    nom            VARCHAR(64)  NOT NULL,
    prenom         VARCHAR(64)  NOT NULL,
    date_naissance DATE         NOT NULL,
    adresse        VARCHAR(128),
    telephone      VARCHAR(20),
    email          VARCHAR(128),
    nir            CHAR(15)     NOT NULL,      -- numéro de sécurité sociale, en clair
    analyse        VARCHAR(32)  NOT NULL,
    valeur         VARCHAR(16)  NOT NULL,
    unite          VARCHAR(16),
    rendu_le       DATETIME     NOT NULL,
    INDEX idx_nir (nir)
);

INSERT INTO patients
    (id, nom, prenom, date_naissance, adresse, telephone, email,
     nir, analyse, valeur, unite, rendu_le) VALUES
  (1,  'Marchand',  'Alicie',  '1985-07-14', '18 rue des Lilas, 59210 Coudekerque-Village', '03 28 00 11 22', 'a.marchand@exemple.fr',  '285075921504281', 'Glycémie à jeun',   '1.08',  'g/L',    '2026-11-05 08:12:00'),
  (2,  'Ferrand',   'Bruno',   '1972-03-02', '7 chemin des Ares, 34200 Sète',               '04 67 12 34 56', 'b.ferrand@exemple.fr',  '172033421805614', 'Créatinine',        '88',    'µmol/L', '2026-11-05 07:41:00'),
  (3,  'Bensaïd',   'Chloé',   '1990-11-27', '24 rue de Vaugirard, 75006 Paris',            '01 45 44 07 18', 'c.bensaid@exemple.fr',  '290117510603133', 'TSH',               '2.1',   'mUI/L',  '2026-11-04 16:05:00'),
  (4,  'Oliveira',  'Damien',  '1964-05-09', '61 boulevard Baille, 13005 Marseille',        '04 91 33 72 05', 'd.oliveira@exemple.fr', '164051309502867', 'Cholestérol LDL',   '1.22',  'g/L',    '2026-11-05 09:26:00'),
  (5,  'Vasseur',   'Élodie',  '1978-09-21', '9 rue de Sully, 38100 Grenoble',              '04 76 51 20 63', 'e.vasseur@exemple.fr',  '278093818504775', 'HbA1c',             '5.4',   '%',      '2026-11-04 11:48:00'),
  (6,  'Benali',    'Farid',   '1953-01-30', '3 allée des Tilleuls, 91080 Évry-Courcouronnes', '01 60 87 41 92', 'f.benali@exemple.fr', '153019124401986', 'CRP',               '3',     'mg/L',   '2026-11-05 10:02:00'),
  (7,  'Poncet',    'Gaëlle',  '1996-06-11', '142 rue Paul Bert, 69003 Lyon',               '04 78 62 15 30', 'g.poncet@exemple.fr',   '296066926607323', 'Hémoglobine',       '13.9',  'g/dL',   '2026-11-04 14:19:00'),
  (8,  'Schneider', 'Hugo',    '1947-12-05', '27 route du Polygone, 67100 Strasbourg',      '03 88 30 76 14', 'h.schneider@exemple.fr','147126721405234', 'D-dimères',         '210',   'ng/mL',  '2026-11-05 06:55:00'),
  (9,  'Da Costa',  'Inès',    '2001-04-18', '53 avenue de Reynerie, 31400 Toulouse',       '05 61 47 88 21', 'i.dacosta@exemple.fr',  '201043115506190', 'Sodium',            '139',   'mmol/L', '2026-11-05 12:33:00'),
  (10, 'Rivemale',  'Jules',   '1988-08-23', '12 rue des Martyrs, 07200 Aubenas',           '04 75 36 09 47', 'j.rivemale@exemple.fr', '188080714603487', 'Kalium',            '4.2',   'mmol/L', '2026-11-04 09:07:00'),
  (11, 'Delaunay',  'Karine',  '1969-02-14', '48 avenue de Paris, 78000 Versailles',        '01 39 20 65 08', 'k.delaunay@exemple.fr', '269027807908838', 'ALAT',              '26',    'U/L',    '2026-11-05 15:24:00'),
  (12, 'Fabre',     'Loïc',    '1993-10-31', '90 chemin de la Croix, 84000 Avignon',        '04 90 85 32 76', 'l.fabre@exemple.fr',    '193108410101537', 'Vitamine 25-OH-D',  '28',    'ng/mL',  '2026-11-04 17:52:00'),
  (13, 'Aubry',     'Marlène', '1959-07-08', '3 rue d''Aguesseau, 92100 Boulogne-Billancourt', '01 46 03 51 39', 'm.aubry@exemple.fr',  '259079232804677', 'Ferritine',         '145',   'µg/L',   '2026-11-05 11:16:00'),
  (14, 'Kessaï',    'Nadir',   '1981-03-19', '88 rue Saint-Maur, 75011 Paris',              '01 43 57 24 90', 'n.kessai@exemple.fr',   '181037534009703', 'Acide urique',      '52',    'mg/L',   '2026-11-05 13:47:00'),
  (15, 'Renaud',    'Olivia',  '1975-11-26', '21 rue de la Porte, 29200 Brest',             '02 98 44 61 05', 'o.renaud@exemple.fr',   '275112909602387', 'Bilirubine totale', '12',    'µmol/L', '2026-11-04 10:38:00');
