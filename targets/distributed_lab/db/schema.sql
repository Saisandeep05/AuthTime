-- AuthTime Distributed Authorization Laboratory Schema
-- PostgreSQL 16+ Production-Grade Schema for Revocation Propagation Testing

CREATE TABLE IF NOT EXISTS users (
    id VARCHAR(64) PRIMARY KEY,
    username VARCHAR(128) NOT NULL UNIQUE,
    email VARCHAR(255) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS roles (
    id VARCHAR(64) PRIMARY KEY,
    name VARCHAR(64) NOT NULL UNIQUE,
    description TEXT
);

CREATE TABLE IF NOT EXISTS user_roles (
    user_id VARCHAR(64) REFERENCES users(id) ON DELETE CASCADE,
    role_id VARCHAR(64) REFERENCES roles(id) ON DELETE CASCADE,
    assigned_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (user_id, role_id)
);

CREATE TABLE IF NOT EXISTS authorization_versions (
    user_id VARCHAR(64) PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    auth_version INTEGER DEFAULT 1 NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS revocation_events (
    event_id VARCHAR(64) PRIMARY KEY,
    user_id VARCHAR(64) NOT NULL,
    revocation_type VARCHAR(64) NOT NULL, -- 'ROLE_DEMOTION', 'SESSION_REVOCATION', 'TOKEN_INVALIDATION'
    previous_role VARCHAR(64),
    new_role VARCHAR(64),
    authoritative_timestamp DOUBLE PRECISION NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Pre-populate default reference lab users
INSERT INTO users (id, username, email) VALUES
    ('admin1', 'admin1', 'admin1@authtime.local'),
    ('user1', 'user1', 'user1@authtime.local'),
    ('svc1', 'svc1', 'svc1@authtime.local')
ON CONFLICT (id) DO NOTHING;

INSERT INTO roles (id, name, description) VALUES
    ('Admin', 'Admin', 'Full administrative access'),
    ('Finance Admin', 'Finance Admin', 'Finance administrative access'),
    ('User', 'User', 'Standard user access'),
    ('Guest', 'Guest', 'Guest read-only access')
ON CONFLICT (id) DO NOTHING;

INSERT INTO user_roles (user_id, role_id) VALUES
    ('admin1', 'Admin'),
    ('user1', 'User')
ON CONFLICT DO NOTHING;

INSERT INTO authorization_versions (user_id, auth_version) VALUES
    ('admin1', 1),
    ('user1', 1)
ON CONFLICT DO NOTHING;
