-- Comptes du portail fournis par le sujet (données fictives) — à charger dans la base valmont.
SET NAMES utf8mb4;
USE valmont;
DROP TABLE IF EXISTS comptes_portail;
CREATE TABLE comptes_portail (
    id          INT PRIMARY KEY,
    patient_id  INT         NOT NULL,   -- référence patients(id)
    identifiant VARCHAR(32) NOT NULL,
    sel         CHAR(32)    NOT NULL,   -- sel hexadécimal de 16 octets, unique par compte
    empreinte   CHAR(64)    NOT NULL,   -- PBKDF2-HMAC-SHA-256, 100 000 itérations
    UNIQUE KEY uq_identifiant (identifiant)
);

INSERT INTO comptes_portail (id, patient_id, identifiant, sel, empreinte) VALUES
  (1, 1,  'marchand.a',  '9f2c41b0d7e38a5c614f0b9d2e77a3c4', '452eacfe75a54c3d374ad9fa037eb8d59e13e3a7f9690e995df588b66d9c99a6'),
  (2, 2,  'ferrand.b',   '31b8ae04c9d25f7e0a6c18bd45f2e970', '56df327891eebd7b5d235a7ff12ed34f8eb5e755ecffa3a8fbf9b97b2b8e8b21'),
  (3, 3,  'bensaid.c',   'c47d9e12f308a5b6de9174c0825b3af1', 'be04bae8b804547c31689121719fe028221db6ca00913c61158eaed7124593b9'),
  (4, 4,  'oliveira.d',  '7a05c3e8b46192fd30e97ba1c46d8502', '6aed73eaea617cf35ab31ed7d5cf9a0689bf4df48f5f98e619694c7dd1f3ed58'),
  (5, 5,  'vasseur.e',   'e28f10b7d5a34c960b82f17ac35e6d94', '15da2ee67c048211b4af751eb0d60f07bd8e68c32fb06dc497f44347baffe9ad'),
  (6, 6,  'benali.f',    '0b6d94a1cf73e285d90a63b17f42c8e5', '8a4ccca287710f7a8cfef3fa91e6b014d737bce25bd85abab3f85c054650633c');
