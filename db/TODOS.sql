
CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(250) NOT NULL UNIQUE,
    password VARCHAR(250) NOT NULL
);

/*
CREATE TABLE todos (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    content VARCHAR(100),
    due DATETIME,
    FOREIGN KEY (user_id) REFERENCES users(id)
);
*/

CREATE TABLE pc (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    status TEXT DEFAULT 'gebaut',
    gesamtpreis REAL DEFAULT 0
);

CREATE TABLE pc_komponenten (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    typ TEXT NOT NULL,            
    marke TEXT,
    modell TEXT,
    preis REAL NOT NULL,
    anzahl INTEGER DEFAULT 1,
    pc_id INTEGER,                
    FOREIGN KEY (pc_id) REFERENCES pc(id)
);


CREATE TABLE cpu (
    id INTEGER PRIMARY KEY,
    frequenz_ghz REAL,
    watt INTEGER,
    FOREIGN KEY (id) REFERENCES pc_komponenten(id)
);


CREATE TABLE gpu (
    id INTEGER PRIMARY KEY,
    vram INTEGER,
    FOREIGN KEY (id) REFERENCES pc_komponenten(id)
);


CREATE TABLE ram (
    id INTEGER PRIMARY KEY,
    speichermenge_gb INTEGER,
    cl_rating TEXT,
    FOREIGN KEY (id) REFERENCES pc_komponenten(id)
);

CREATE TABLE mobo (
    id INTEGER PRIMARY KEY,
    FOREIGN KEY (id) REFERENCES pc_komponenten(id)
);

CREATE TABLE psu (
    id INTEGER PRIMARY KEY,
    watt INTEGER,
    FOREIGN KEY (id) REFERENCES pc_komponenten(id)
);


CREATE TABLE ssd (
    id INTEGER PRIMARY KEY,
    speichermenge_gb INTEGER,
    FOREIGN KEY (id) REFERENCES pc_komponenten(id)
);


CREATE TABLE pc_case (
    id INTEGER PRIMARY KEY,
    FOREIGN KEY (id) REFERENCES pc_komponenten(id)
);


CREATE TABLE fans (
    id INTEGER PRIMARY KEY,
    FOREIGN KEY (id) REFERENCES pc_komponenten(id)
);


CREATE TABLE kuehler (
    id INTEGER PRIMARY KEY,
    FOREIGN KEY (id) REFERENCES pc_komponenten(id)
);

CREATE TABLE argb (
    id INTEGER PRIMARY KEY,
    FOREIGN KEY (id) REFERENCES pc_komponenten(id)
);


CREATE TABLE extensions (
    id INTEGER PRIMARY KEY,
    FOREIGN KEY (id) REFERENCES pc_komponenten(id)
);

CREATE TABLE sales (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    pc_id INTEGER NOT NULL,
    verkaufspreis REAL NOT NULL,
    verkauft_am DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (pc_id) REFERENCES pc(id)
);
