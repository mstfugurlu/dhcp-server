package store

const schema = `
CREATE TABLE IF NOT EXISTS scopes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    network TEXT NOT NULL,
    subnet_mask TEXT NOT NULL,
    range_start TEXT NOT NULL,
    range_end TEXT NOT NULL,
    gateway TEXT NOT NULL,
    dns TEXT NOT NULL,
    lease_duration INTEGER NOT NULL DEFAULT 86400,
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS leases (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scope_id INTEGER NOT NULL,
    ip TEXT NOT NULL,
    mac TEXT NOT NULL,
    hostname TEXT,
    expires_at DATETIME NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (scope_id) REFERENCES scopes(id),
    UNIQUE(ip)
);

CREATE TABLE IF NOT EXISTS reservations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scope_id INTEGER NOT NULL,
    ip TEXT NOT NULL,
    mac TEXT NOT NULL,
    hostname TEXT,
    description TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (scope_id) REFERENCES scopes(id),
    UNIQUE(ip),
    UNIQUE(mac)
);

CREATE TABLE IF NOT EXISTS excluded_ranges (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scope_id INTEGER NOT NULL,
    range_start TEXT NOT NULL,
    range_end TEXT NOT NULL,
    description TEXT,
    FOREIGN KEY (scope_id) REFERENCES scopes(id)
);

CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS lease_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scope_id INTEGER NOT NULL,
    ip TEXT NOT NULL,
    mac TEXT NOT NULL,
    hostname TEXT,
    action TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_leases_mac ON leases(mac);
CREATE INDEX IF NOT EXISTS idx_leases_expires ON leases(expires_at);
CREATE INDEX IF NOT EXISTS idx_reservations_mac ON reservations(mac);
`
