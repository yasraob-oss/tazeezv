import { pgTable, text, jsonb, integer, timestamp } from "drizzle-orm/pg-core";

// Shared platform data (events, volunteers, records, accounts…) without login secrets.
export const appState = pgTable("app_state", {
  id: text().primaryKey(),
  data: jsonb().notNull(),
  revision: integer().notNull().default(1),
  updatedAt: timestamp("updated_at").defaultNow().notNull(),
});

// PBKDF2 salt/hash per account or registration request. Never sent to the browser.
export const credentials = pgTable("credentials", {
  ownerId: text("owner_id").primaryKey(),
  salt: text().notNull(),
  hash: text().notNull(),
});

export const sessions = pgTable("sessions", {
  token: text().primaryKey(),
  accountId: text("account_id").notNull(),
  expiresAt: timestamp("expires_at").notNull(),
});
