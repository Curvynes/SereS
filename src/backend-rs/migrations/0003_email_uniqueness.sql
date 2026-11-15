-- Triggers enforce uniqueness for new writes while retaining any duplicate
-- addresses already present in an older installation.
CREATE INDEX IF NOT EXISTS idx_users_email_nocase ON users(email COLLATE NOCASE);

CREATE TRIGGER IF NOT EXISTS users_email_unique_insert
BEFORE INSERT ON users
WHEN NEW.email IS NOT NULL AND EXISTS (
    SELECT 1 FROM users WHERE email = NEW.email COLLATE NOCASE
)
BEGIN
    SELECT RAISE(ABORT, 'Email already in use');
END;

CREATE TRIGGER IF NOT EXISTS users_email_unique_update
BEFORE UPDATE OF email ON users
WHEN NEW.email IS NOT OLD.email AND NEW.email IS NOT NULL AND EXISTS (
    SELECT 1 FROM users WHERE email = NEW.email COLLATE NOCASE AND rowid != OLD.rowid
)
BEGIN
    SELECT RAISE(ABORT, 'Email already in use');
END;
