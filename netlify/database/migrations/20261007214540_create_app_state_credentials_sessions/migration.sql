CREATE TABLE "app_state" (
	"id" text PRIMARY KEY,
	"data" jsonb NOT NULL,
	"revision" integer DEFAULT 1 NOT NULL,
	"updated_at" timestamp DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "credentials" (
	"owner_id" text PRIMARY KEY,
	"salt" text NOT NULL,
	"hash" text NOT NULL
);
--> statement-breakpoint
CREATE TABLE "sessions" (
	"token" text PRIMARY KEY,
	"account_id" text NOT NULL,
	"expires_at" timestamp NOT NULL
);
