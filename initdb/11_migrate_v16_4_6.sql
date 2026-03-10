-- ArgusWatch v16.4.7 Session B: Persistent user accounts
-- Replaces the in-memory _users dict in auth.py

CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(255) UNIQUE NOT NULL,
    hashed_password VARCHAR(255) NOT NULL,
    role VARCHAR(50) DEFAULT 'analyst',
    active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT NOW(),
    last_login TIMESTAMP
);

CREATE INDEX IF NOT EXISTS ix_users_username ON users(username);

-- Bootstrap admin will be created by auth.py on first startup if table is empty
