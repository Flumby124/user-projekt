
CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(250) NOT NULL UNIQUE,
    password VARCHAR(250) NOT NULL
);

ALTER TABLE pc
ADD COLUMN user_id INT NOT NULL DEFAULT 1
;

CREATE TABLE pc (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    status VARCHAR(50) DEFAULT 'gebaut',
    gesamtpreis DECIMAL(10,2) DEFAULT 0,
    user_id INT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);


CREATE TABLE pc_komponenten (
    id INT AUTO_INCREMENT PRIMARY KEY,
    typ ENUM(
        'cpu','gpu','ram','psu','ssd','pc_case',
        'fans','kuehler','argb','extensions','mobo'
    ) NOT NULL,
    marke VARCHAR(255),
    modell VARCHAR(255),
    preis DECIMAL(10,2) NOT NULL,
    anzahl INT NOT NULL DEFAULT 1,
    pc_id INT NULL,
    user_id INT NOT NULL,

    FOREIGN KEY (pc_id) REFERENCES pc(id) ON DELETE SET NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,

    CHECK (anzahl >= 0)
);


CREATE TABLE cpu (
    id INT PRIMARY KEY,
    frequenz_ghz DECIMAL(4,2),
    watt INT,
    FOREIGN KEY (id) REFERENCES pc_komponenten(id) ON DELETE CASCADE
);

CREATE TABLE gpu (
    id INT PRIMARY KEY,
    vram INT,
    FOREIGN KEY (id) REFERENCES pc_komponenten(id) ON DELETE CASCADE
);

CREATE TABLE ram (
    id INT PRIMARY KEY,
    speichermenge_gb INT,
    cl_rating VARCHAR(50),
    FOREIGN KEY (id) REFERENCES pc_komponenten(id) ON DELETE CASCADE
);

CREATE TABLE psu (
    id INT PRIMARY KEY,
    watt INT,
    FOREIGN KEY (id) REFERENCES pc_komponenten(id) ON DELETE CASCADE
);

CREATE TABLE ssd (
    id INT PRIMARY KEY,
    speichermenge_gb INT,
    FOREIGN KEY (id) REFERENCES pc_komponenten(id) ON DELETE CASCADE
);

CREATE TABLE mobo (
    id INT PRIMARY KEY,
    FOREIGN KEY (id) REFERENCES pc_komponenten(id) ON DELETE CASCADE
);

CREATE TABLE pc_case (
    id INT PRIMARY KEY,
    FOREIGN KEY (id) REFERENCES pc_komponenten(id) ON DELETE CASCADE
);

CREATE TABLE fans (
    id INT PRIMARY KEY,
    FOREIGN KEY (id) REFERENCES pc_komponenten(id) ON DELETE CASCADE
);

CREATE TABLE kuehler (
    id INT PRIMARY KEY,
    FOREIGN KEY (id) REFERENCES pc_komponenten(id) ON DELETE CASCADE
);

CREATE TABLE argb (
    id INT PRIMARY KEY,
    FOREIGN KEY (id) REFERENCES pc_komponenten(id) ON DELETE CASCADE
);

CREATE TABLE extensions (
    id INT PRIMARY KEY,
    FOREIGN KEY (id) REFERENCES pc_komponenten(id) ON DELETE CASCADE
);


CREATE TABLE sales (
    id INT AUTO_INCREMENT PRIMARY KEY,
    pc_id INT NOT NULL,
    verkaufspreis DECIMAL(10,2) NOT NULL,
    verkauft_am DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (pc_id) REFERENCES pc(id) ON DELETE CASCADE
);
