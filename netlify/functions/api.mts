import type { Config } from "@netlify/functions";
import { eq, inArray, lt, notInArray } from "drizzle-orm";
import { pbkdf2, randomBytes, timingSafeEqual } from "node:crypto";
import { promisify } from "node:util";
import { db } from "../../db/index.js";
import { appState, credentials, sessions } from "../../db/schema.js";

const STATE_ID = "main";
const SESSION_HOURS = 8;
const derive = promisify(pbkdf2);

type Credential = { salt: string; hash: string };
type Account = {
  id: string;
  role: "volunteer" | "admin" | "association";
  email: string;
  name: string;
  active?: boolean;
  approvalStatus?: string;
  volunteerId?: string;
  registrationId?: string;
  demo?: boolean;
  credential?: Credential;
  [key: string]: unknown;
};
type Registration = { id: string; email: string; status: string; reviewNote?: string; credential?: Credential; [key: string]: unknown };
type State = {
  accounts?: Account[];
  registrationRequests?: Registration[];
  volunteers?: { id: string; active?: boolean }[];
  [key: string]: unknown;
};

const json = (body: unknown, status = 200) => Response.json(body, { status });
const fail = (message: string, status = 400) => json({ error: message }, status);
const isHex = (value: unknown, length?: number) =>
  typeof value === "string" && /^[0-9a-f]+$/.test(value) && (!length || value.length === length);
const validCredential = (c: unknown): c is Credential =>
  !!c && isHex((c as Credential).salt, 32) && isHex((c as Credential).hash, 64);

// Same normalisation as the browser: Arabic-Indic digits are accepted as Western digits.
function codeCandidates(code: string) {
  const normalized = /^[0-9٠-٩۰-۹]+$/.test(code)
    ? code.replace(/[٠-٩]/g, (c) => String(c.charCodeAt(0) - 1632)).replace(/[۰-۹]/g, (c) => String(c.charCodeAt(0) - 1776))
    : code;
  return [...new Set([code, normalized])];
}

async function hashCode(code: string, salt = randomBytes(16).toString("hex")): Promise<Credential> {
  const hash = await derive(code, Buffer.from(salt, "hex"), 100000, 32, "sha256");
  return { salt, hash: hash.toString("hex") };
}

async function verifyCode(code: string, credential?: Credential | null) {
  if (!credential) return false;
  for (const candidate of codeCandidates(code)) {
    const { hash } = await hashCode(candidate, credential.salt);
    if (timingSafeEqual(Buffer.from(hash, "hex"), Buffer.from(credential.hash, "hex"))) return true;
  }
  return false;
}

async function loadState() {
  const [row] = await db.select().from(appState).where(eq(appState.id, STATE_ID));
  return row ? { state: row.data as State, revision: row.revision } : null;
}

async function getCredential(ownerId: string) {
  const [row] = await db.select().from(credentials).where(eq(credentials.ownerId, ownerId));
  return row ? { salt: row.salt, hash: row.hash } : null;
}

async function setCredential(ownerId: string, credential: Credential) {
  await db
    .insert(credentials)
    .values({ ownerId, ...credential })
    .onConflictDoUpdate({ target: credentials.ownerId, set: credential });
}

// Pulls credential objects out of the shared state so hashes never reach other browsers.
function stripCredentials(state: State) {
  const found = new Map<string, Credential>();
  for (const list of [state.accounts, state.registrationRequests]) {
    for (const item of list || []) {
      if (validCredential(item.credential)) found.set(item.id, { salt: item.credential.salt, hash: item.credential.hash });
      delete item.credential;
    }
  }
  return found;
}

function accountUsable(state: State, account?: Account) {
  if (!account || !account.active) return false;
  if (account.approvalStatus && account.approvalStatus !== "approved") return false;
  if (account.role === "volunteer") return !!state.volunteers?.find((v) => v.id === account.volunteerId)?.active;
  return true;
}

async function createSession(accountId: string) {
  const token = randomBytes(32).toString("hex");
  const expiresAt = new Date(Date.now() + SESSION_HOURS * 3600 * 1000);
  await db.delete(sessions).where(lt(sessions.expiresAt, new Date()));
  await db.insert(sessions).values({ token, accountId, expiresAt });
  return { token, expires: expiresAt.getTime() };
}

async function authenticate(req: Request) {
  const token = req.headers.get("authorization")?.replace(/^Bearer\s+/i, "");
  if (!token || !isHex(token, 64)) return null;
  const [row] = await db.select().from(sessions).where(eq(sessions.token, token));
  if (!row || row.expiresAt.getTime() < Date.now()) return null;
  const current = await loadState();
  if (!current) return null;
  const account = current.state.accounts?.find((a) => a.id === row.accountId);
  if (!accountUsable(current.state, account)) return null;
  return { token, account: account!, ...current };
}

async function readBody(req: Request) {
  try {
    return (await req.json()) as Record<string, any>;
  } catch {
    return {};
  }
}

const cleanEmail = (value: unknown) => String(value ?? "").trim().toLowerCase();
const validEmail = (email: string) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) && email.length <= 100;
const validCode = (code: string) => code.length >= 6 && code.length <= 128;

export default async (req: Request) => {
  const route = new URL(req.url).pathname.replace(/^\/api\/?/, "");

  try {
    if (route === "status" && req.method === "GET") {
      return json({ initialized: !!(await loadState()) });
    }

    // One-time setup: creates the first team admin and stores the starting data on the server.
    if (route === "setup" && req.method === "POST") {
      if (await loadState()) return fail("تم تجهيز المنصة مسبقًا. سجّل الدخول بحساب الإدارة.", 409);
      const body = await readBody(req);
      const state = (body.state && typeof body.state === "object" ? body.state : {}) as State;
      const name = String(body.name ?? "").trim(), email = cleanEmail(body.email), code = String(body.code ?? "");
      if (!name || !validEmail(email) || !validCode(code)) return fail("أكمل الاسم والإيميل ورمزًا من ٦ محارف على الأقل.");
      // Demo accounts share a public code, so they are never carried to the server.
      state.accounts = (state.accounts || []).filter((a) => !a.demo && a.email !== email);
      state.registrationRequests = state.registrationRequests || [];
      const kept = stripCredentials(state);
      const admin: Account = { id: "admin-" + randomBytes(6).toString("hex"), role: "admin", name, email, active: true, approvalStatus: "approved", revision: 1, demo: false };
      state.accounts.push(admin);
      await db.insert(appState).values({ id: STATE_ID, data: state, revision: 1 });
      for (const [id, credential] of kept) await setCredential(id, credential);
      await setCredential(admin.id, await hashCode(code));
      const session = await createSession(admin.id);
      return json({ ...session, accountId: admin.id, role: admin.role, accountRevision: 1, state, revision: 1 });
    }

    if (route === "login" && req.method === "POST") {
      const body = await readBody(req);
      const email = cleanEmail(body.email), code = String(body.code ?? "");
      const current = await loadState();
      if (!current) return fail("المنصة غير مجهزة بعد.", 409);
      const { state } = current;
      const account = state.accounts?.find((a) => a.email.trim().toLowerCase() === email);
      if (!account) {
        const request = [...(state.registrationRequests || [])].reverse().find((r) => r.email === email);
        if (request && (await verifyCode(code, await getCredential(request.id)))) {
          const message =
            request.status === "pending"
              ? "طلب تسجيل حسابك بانتظار موافقة إدارة الفريق."
              : request.status === "rejected"
                ? "لم توافق الإدارة على الطلب. " + (request.reviewNote || "يمكنك تقديم طلب جديد.")
                : "راجع إدارة الفريق لتفعيل حسابك.";
          return fail(message, 403);
        }
        return fail("الإيميل أو رمز الدخول غير صحيح. إذا لم يكن لديك حساب، اختر تسجيل حساب جديد.", 401);
      }
      if (!(await verifyCode(code, await getCredential(account.id)))) return fail("الإيميل أو رمز الدخول غير صحيح.", 401);
      if (account.approvalStatus && account.approvalStatus !== "approved") return fail("الحساب بانتظار موافقة إدارة الفريق.", 403);
      if (!accountUsable(state, account)) return fail("الحساب غير مفعّل. تواصل مع إدارة الفريق.", 403);
      const session = await createSession(account.id);
      return json({ ...session, accountId: account.id, role: account.role, accountRevision: account.revision, state, revision: current.revision });
    }

    if (route === "register" && req.method === "POST") {
      const body = await readBody(req);
      const name = String(body.name ?? "").trim().slice(0, 80), email = cleanEmail(body.email), code = String(body.code ?? "");
      const role = String(body.role ?? ""), department = String(body.department ?? "").trim().slice(0, 80);
      if (!name || !validEmail(email) || !validCode(code) || !["volunteer", "admin", "association"].includes(role))
        return fail("راجع البيانات المطلوبة ثم حاول مجددًا.");
      const current = await loadState();
      if (!current) return fail("المنصة غير مجهزة بعد.", 409);
      const { state } = current;
      if (state.accounts?.some((a) => a.email.toLowerCase() === email)) return fail("هذا الإيميل مرتبط بحساب موجود. سجّل الدخول به.", 409);
      if (state.registrationRequests?.some((r) => r.email === email && r.status === "pending"))
        return fail("يوجد طلب معلق بهذا الإيميل.", 409);
      const request: Registration = {
        id: "registration-" + randomBytes(6).toString("hex"),
        name, email, role, department, status: "pending",
        created: new Date().toISOString().slice(0, 10), createdAt: new Date().toISOString(), reviewNote: "",
      };
      state.registrationRequests = [...(state.registrationRequests || []), request];
      await setCredential(request.id, await hashCode(code));
      await db.update(appState).set({ data: state, revision: current.revision + 1, updatedAt: new Date() }).where(eq(appState.id, STATE_ID));
      return json({ ok: true }, 201);
    }

    const auth = await authenticate(req);
    if (!auth) return fail("انتهت الجلسة. سجّل الدخول مجددًا.", 401);

    if (route === "logout" && req.method === "POST") {
      await db.delete(sessions).where(eq(sessions.token, auth.token));
      return json({ ok: true });
    }

    if (route === "state" && req.method === "GET") {
      return json({ state: auth.state, revision: auth.revision });
    }

    if (route === "state" && req.method === "PUT") {
      const body = await readBody(req);
      const incoming = body.state as State;
      if (!incoming || typeof incoming !== "object" || !Array.isArray(incoming.accounts)) return fail("بيانات غير صالحة.");
      if (Number(body.revision) !== auth.revision) return json({ error: "conflict", state: auth.state, revision: auth.revision }, 409);
      const isAdmin = auth.account.role === "admin";
      const newCredentials = stripCredentials(incoming);
      if (!isAdmin) {
        // Only team admins manage accounts and registration requests.
        incoming.accounts = auth.state.accounts;
        incoming.registrationRequests = auth.state.registrationRequests;
        for (const id of [...newCredentials.keys()]) if (id !== auth.account.id) newCredentials.delete(id);
      } else if (!incoming.accounts.some((a) => a.role === "admin" && a.active)) {
        return fail("يجب إبقاء حساب إدارة نشط واحد على الأقل.");
      }
      const revision = auth.revision + 1;
      await db.update(appState).set({ data: incoming, revision, updatedAt: new Date() }).where(eq(appState.id, STATE_ID));
      const requestIds = (incoming.registrationRequests || []).map((r) => r.id);
      for (const [id, credential] of newCredentials) if (!requestIds.includes(id)) await setCredential(id, credential);
      // Approved registrations inherit the code the applicant chose.
      for (const account of incoming.accounts) {
        if (account.registrationId && !newCredentials.has(account.id) && !(await getCredential(account.id))) {
          const fromRequest = await getCredential(account.registrationId);
          if (fromRequest) await setCredential(account.id, fromRequest);
        }
      }
      const owners = [...incoming.accounts.map((a) => a.id), ...requestIds];
      await db.delete(credentials).where(notInArray(credentials.ownerId, owners));
      const removed = (auth.state.accounts || []).map((a) => a.id).filter((id) => !owners.includes(id));
      if (removed.length) await db.delete(sessions).where(inArray(sessions.accountId, removed));
      return json({ revision });
    }

    return fail("Not found", 404);
  } catch (error) {
    console.error(error);
    return fail("تعذّر الاتصال بالخادم. حاول مجددًا.", 500);
  }
};

export const config: Config = { path: ["/api/status", "/api/setup", "/api/login", "/api/register", "/api/logout", "/api/state"] };
