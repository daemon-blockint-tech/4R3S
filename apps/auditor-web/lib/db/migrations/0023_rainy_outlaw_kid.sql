ALTER TABLE "plans" ADD COLUMN "capabilities" jsonb DEFAULT '[]'::jsonb NOT NULL;
