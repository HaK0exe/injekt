-- lab-hard/db/mysql/seed.sql — MySQL 8.4 HARD. Idempotent reset seed.
CREATE DATABASE IF NOT EXISTS hard CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci;
USE hard;

DROP TABLE IF EXISTS `verification_token`;
DROP TABLE IF EXISTS `credentials`;
DROP TABLE IF EXISTS `config`;
DROP TABLE IF EXISTS `profiles`;
DROP TABLE IF EXISTS `canary`;
DROP TABLE IF EXISTS `users`;

CREATE TABLE `users` (
  `id` INT AUTO_INCREMENT PRIMARY KEY,
  `username` VARCHAR(64) NOT NULL UNIQUE,
  `email` VARCHAR(128) NOT NULL,
  `secret` VARCHAR(256) NOT NULL,
  `is_admin` TINYINT NOT NULL DEFAULT 0
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE `verification_token` (
  `id` INT AUTO_INCREMENT PRIMARY KEY,
  `user_id` INT NULL,
  `token` VARCHAR(255) NOT NULL UNIQUE,
  `api_key` VARCHAR(255) NOT NULL,
  `expires_at` TIMESTAMP NULL DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE `credentials` (
  `id` INT AUTO_INCREMENT PRIMARY KEY,
  `credential_name` VARCHAR(128) NOT NULL UNIQUE,
  `credential_values` JSON NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE `config` (
  `id` INT AUTO_INCREMENT PRIMARY KEY,
  `param_name` VARCHAR(128) NOT NULL UNIQUE,
  `environment_variables` JSON NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- second-order store: nick brut, rejoué dans /h/profile
CREATE TABLE `profiles` (
  `id` INT AUTO_INCREMENT PRIMARY KEY,
  `nick` VARCHAR(256) NOT NULL,
  `bio` VARCHAR(512) NOT NULL DEFAULT ''
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE `canary` (
  `id` INT PRIMARY KEY,
  `marker` VARCHAR(64) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

INSERT INTO `users` (`username`, `email`, `secret`, `is_admin`) VALUES
  ('alice', 'alice@example.com', 'flag-hard-alice-7f3a2c91e4', 0),
  ('bob',   'bob@example.com',   'flag-hard-bob-b81d44f0a2',   0),
  ('admin', 'admin@example.com', 'flag-hard-admin-9c4e1d77f0', 1);

INSERT INTO `verification_token` (`user_id`, `token`, `api_key`) VALUES
  (1, 'litellm-token-alice-01', 'sk-litellm-alice-HARD-001'),
  (3, 'litellm-token-admin-01', 'sk-litellm-admin-HARD-002');

INSERT INTO `credentials` (`credential_name`, `credential_values`) VALUES
  ('openai-prod', '{"openai_api_key": "sk-proj-hard-AAA111", "model": "gpt-4o"}'),
  ('anthropic-prod', '{"anthropic_api_key": "sk-ant-hard-BBB222"}');

INSERT INTO `config` (`param_name`, `environment_variables`) VALUES
  ('prod', '{"OPENAI_API_KEY": "sk-proj-hard-AAA111", "ANTHROPIC_API_KEY": "sk-ant-hard-BBB222", "AWS_SECRET_ACCESS_KEY": "aws-hard-CCC333"}');

INSERT INTO `profiles` (`nick`, `bio`) VALUES ('alice', 'hello'), ('bob', 'world');

-- Tripwire: runner asserts this row still reads exactly 'untouched'.
INSERT INTO `canary` (`id`, `marker`) VALUES (1, 'untouched');
