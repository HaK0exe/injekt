-- bench/db/mysql/seed.sql — MySQL 8.4 LTS. Idempotent reset seed.
CREATE DATABASE IF NOT EXISTS bench;
USE bench;

DROP TABLE IF EXISTS vault;
DROP TABLE IF EXISTS canary;
DROP TABLE IF EXISTS users;

CREATE TABLE users (
  id INT AUTO_INCREMENT PRIMARY KEY,
  username VARCHAR(64) NOT NULL,
  email VARCHAR(128) NOT NULL,
  password VARCHAR(128) NOT NULL,
  is_admin TINYINT NOT NULL DEFAULT 0
);

CREATE TABLE vault (
  id INT AUTO_INCREMENT PRIMARY KEY,
  owner VARCHAR(64) NOT NULL,
  secret VARCHAR(128) NOT NULL
);

CREATE TABLE canary (
  id INT PRIMARY KEY,
  marker VARCHAR(64) NOT NULL
);

INSERT INTO users (username, email, password, is_admin) VALUES
  ('alice', 'alice@example.com', 'k7 patchwork-drum', 0),
  ('bob',   'bob@example.com',   'harbor lantern-42', 0),
  ('admin', 'admin@example.com', 'sup3r-s3cr3t-pw',   1);

INSERT INTO vault (owner, secret) VALUES
  ('alice', 'flag-sample-alice-1'),
  ('admin', 'flag-sample-admin-2');

-- Tripwire: runner asserts this row still reads exactly 'untouched'.
INSERT INTO canary (id, marker) VALUES (1, 'untouched');
