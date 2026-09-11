-- lab-hard/db/mssql/seed.sql — SQL Server 2022 HARD. Via sqlcmd.
IF DB_ID('hard') IS NULL CREATE DATABASE hard;
GO
USE hard;
GO

DROP TABLE IF EXISTS verification_token;
DROP TABLE IF EXISTS credentials;
DROP TABLE IF EXISTS config;
DROP TABLE IF EXISTS profiles;
DROP TABLE IF EXISTS canary;
DROP TABLE IF EXISTS users;
GO

CREATE TABLE users (
  id INT IDENTITY(1,1) PRIMARY KEY,
  username NVARCHAR(64) NOT NULL UNIQUE,
  email NVARCHAR(128) NOT NULL,
  secret NVARCHAR(256) NOT NULL,
  is_admin SMALLINT NOT NULL CONSTRAINT DF_hard_users_is_admin DEFAULT 0
);

CREATE TABLE verification_token (
  id INT IDENTITY(1,1) PRIMARY KEY,
  user_id INT NULL REFERENCES users(id) ON DELETE CASCADE,
  token NVARCHAR(255) NOT NULL UNIQUE,
  api_key NVARCHAR(255) NOT NULL,
  expires_at DATETIME2 NULL
);

CREATE TABLE credentials (
  id INT IDENTITY(1,1) PRIMARY KEY,
  credential_name NVARCHAR(128) NOT NULL UNIQUE,
  credential_values NVARCHAR(MAX) NOT NULL
    CONSTRAINT CK_hard_credentials_json CHECK (ISJSON(credential_values)=1)
);

CREATE TABLE config (
  id INT IDENTITY(1,1) PRIMARY KEY,
  param_name NVARCHAR(128) NOT NULL UNIQUE,
  environment_variables NVARCHAR(MAX) NOT NULL
    CONSTRAINT CK_hard_config_json CHECK (ISJSON(environment_variables)=1)
);

CREATE TABLE profiles (
  id INT IDENTITY(1,1) PRIMARY KEY,
  nick NVARCHAR(256) NOT NULL,
  bio NVARCHAR(512) NOT NULL DEFAULT ''
);

CREATE TABLE canary (
  id INT PRIMARY KEY,
  marker NVARCHAR(64) NOT NULL
);
GO

INSERT INTO users (username, email, secret, is_admin) VALUES
  ('alice', 'alice@example.com', 'flag-hard-alice-7f3a2c91e4', 0),
  ('bob',   'bob@example.com',   'flag-hard-bob-b81d44f0a2',   0),
  ('admin', 'admin@example.com', 'flag-hard-admin-9c4e1d77f0', 1);

INSERT INTO verification_token (user_id, token, api_key) VALUES
  (1, 'litellm-token-alice-01', 'sk-litellm-alice-HARD-001'),
  (3, 'litellm-token-admin-01', 'sk-litellm-admin-HARD-002');

INSERT INTO credentials (credential_name, credential_values) VALUES
  ('openai-prod', N'{"openai_api_key": "sk-proj-hard-AAA111", "model": "gpt-4o"}'),
  ('anthropic-prod', N'{"anthropic_api_key": "sk-ant-hard-BBB222"}');

INSERT INTO config (param_name, environment_variables) VALUES
  ('prod', N'{"OPENAI_API_KEY": "sk-proj-hard-AAA111", "ANTHROPIC_API_KEY": "sk-ant-hard-BBB222", "AWS_SECRET_ACCESS_KEY": "aws-hard-CCC333"}');

INSERT INTO profiles (nick, bio) VALUES ('alice', 'hello'), ('bob', 'world');

INSERT INTO canary (id, marker) VALUES (1, 'untouched');
GO
