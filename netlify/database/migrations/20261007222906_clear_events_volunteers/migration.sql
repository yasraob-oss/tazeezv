-- Removes all events, volunteers and volunteer accounts (with their participation records) from the shared platform data.
DELETE FROM "sessions" WHERE "account_id" IN (
	SELECT a->>'id' FROM "app_state", jsonb_array_elements(COALESCE("data"->'accounts', '[]'::jsonb)) a
	WHERE "id" = 'main' AND a->>'role' = 'volunteer'
);
--> statement-breakpoint
DELETE FROM "credentials" WHERE "owner_id" IN (
	SELECT a->>'id' FROM "app_state", jsonb_array_elements(COALESCE("data"->'accounts', '[]'::jsonb)) a
	WHERE "id" = 'main' AND a->>'role' = 'volunteer'
);
--> statement-breakpoint
UPDATE "app_state" SET
	"data" = "data" || jsonb_build_object(
		'events', '[]'::jsonb,
		'volunteers', '[]'::jsonb,
		'records', '[]'::jsonb,
		'bookmarks', '[]'::jsonb,
		'accounts', COALESCE((
			SELECT jsonb_agg(a) FROM jsonb_array_elements(COALESCE("data"->'accounts', '[]'::jsonb)) a
			WHERE a->>'role' IS DISTINCT FROM 'volunteer'
		), '[]'::jsonb)
	),
	"revision" = "revision" + 1,
	"updated_at" = now()
WHERE "id" = 'main';
