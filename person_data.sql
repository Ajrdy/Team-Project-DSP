CREATE TABLE person_data (
    id INT AUTO_INCREMENT PRIMARY KEY,
    first_name VARCHAR(255),
    last_name VARCHAR(255),
    gender BOOLEAN,
    age INT,
    weight FLOAT,
    height FLOAT,
    health_history TEXT
);