-- Add status column to sandboxes (running | suspended)
ALTER TABLE sandboxes ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'running';
