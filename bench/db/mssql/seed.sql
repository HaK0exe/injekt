-- bench/db/mssql/seed.sql — SQL Server 2022. Idempotent reset seed.
-- Executed by the runner via sqlcmd (see bench/runner/run.py).
IF DB_ID('bench') IS NULL CREATE DATABASE bench;
GO
USE bench;
GO

DROP TABLE IF EXISTS vault;
DROP TABLE IF EXISTS canary;
DROP TABLE IF EXISTS users;
GO

CREATE TABLE users (
  id INT IDENTITY(1,1) PRIMARY KEY,
  username NVARCHAR(64) NOT NULL,
  email NVARCHAR(128) NOT NULL,
  password NVARCHAR(128) NOT NULL,
  is_admin SMALLINT NOT NULL DEFAULT 0
);

CREATE TABLE vault (
  id INT IDENTITY(1,1) PRIMARY KEY,
  owner NVARCHAR(64) NOT NULL,
  secret NVARCHAR(128) NOT NULL
);

CREATE TABLE canary (
  id INT PRIMARY KEY,
  marker NVARCHAR(64) NOT NULL
);
GO

INSERT INTO users (username, email, password, is_admin) VALUES
  ('alice', 'alice@example.com', 'k7 patchwork-drum', 0),
  ('bob',   'bob@example.com',   'harbor lantern-42', 0),
  ('admin', 'admin@example.com', 'sup3r-s3cr3t-pw',   1);

INSERT INTO vault (owner, secret) VALUES
  ('alice', 'flag-sample-alice-1'),
  ('admin', 'flag-sample-admin-2');

-- Tripwire: runner asserts this row still reads exactly 'untouched'.
INSERT INTO canary (id, marker) VALUES (1, 'untouched');
GO
