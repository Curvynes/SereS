CREATE INDEX IF NOT EXISTS idx_call_participants_user ON call_participants(user_id, state);

CREATE INDEX IF NOT EXISTS idx_call_signals_to ON call_signals(to_id, id);

CREATE INDEX IF NOT EXISTS idx_calls_chat ON calls(chat_id, ended_at);

CREATE INDEX IF NOT EXISTS idx_files_message ON files(message_id);

CREATE INDEX IF NOT EXISTS idx_key_history_user ON user_key_history(user_id);

CREATE INDEX IF NOT EXISTS idx_key_shares_recipient ON message_key_shares(recipient_id);

CREATE INDEX IF NOT EXISTS idx_members_user ON chat_members(user_id);

CREATE INDEX IF NOT EXISTS idx_messages_chat_rev ON messages(chat_id, rev);

CREATE INDEX IF NOT EXISTS idx_messages_chat_seq ON messages(chat_id, seq);

CREATE INDEX IF NOT EXISTS idx_messages_expires ON messages(expires_at) WHERE expires_at IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_passkeys_user ON passkeys(user_id);

CREATE INDEX IF NOT EXISTS idx_receipts ON receipts(chat_id, user_id, kind, seq);

CREATE INDEX IF NOT EXISTS idx_scheduled_due ON scheduled_messages(send_at);

CREATE INDEX IF NOT EXISTS idx_sessions_user ON user_sessions(user_id);
