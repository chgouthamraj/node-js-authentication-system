CREATE database rbac_system;

CREATE TABLE roles (
  role_id INT PRIMARY KEY AUTO_INCREMENT,
  role_name VARCHAR(255) UNIQUE NOT NULL,
  permissions JSON NOT NULL
);

CREATE TABLE users (
  user_id INT PRIMARY KEY AUTO_INCREMENT,
  username VARCHAR(255) UNIQUE NOT NULL,
  email VARCHAR(255) UNIQUE NOT NULL,
  password VARCHAR(255) NOT NULL,
  salt VARCHAR(255) NOT NULL,
  role_id INT NOT NULL,
  first_name VARCHAR(255),
  last_name VARCHAR(255),
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  FOREIGN KEY (role_id) REFERENCES roles(role_id)
);


CREATE TABLE password_resets (
  reset_token VARCHAR(255) UNIQUE NOT NULL,
  user_id INT NOT NULL,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  expires_at DATETIME NOT NULL,
  FOREIGN KEY (user_id) REFERENCES users(user_id)
);


INSERT INTO roles (role_name, permissions) VALUES
('admin', '{"read": true, "write": true, "delete": true}'),
('user', '{"read": true, "write": false, "delete": false}'),
('hr', '{"read": true, "write": true, "delete": false}');
