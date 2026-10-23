// Connections every signed-in user gets automatically in Local Workspace.
// The mf-db connection goes through /proxy/turso, which adds the real Turso token on the server,
// so the browser only ever holds this placeholder token.
import { SavedConnectionRawLocalStorage } from "@/app/(theme)/connect/saved-connection-storage";
import { LocalConnectionData, localDb } from "@/indexdb";

export const BUILTIN_MF_DB_ID = "builtin-mf-db";

function builtinConnections(origin: string): LocalConnectionData[] {
  const content: SavedConnectionRawLocalStorage = {
    id: BUILTIN_MF_DB_ID,
    name: "mf-db (Turso)",
    driver: "turso",
    url: `${origin}/proxy/turso`,
    token: "server-side",
    label: "blue",
    description: "Shared Turso database. Credentials are kept on the server.",
  };
  return [{ id: BUILTIN_MF_DB_ID, content, created_at: 0, updated_at: 0 }];
}

/** Adds or refreshes the built-in connections in this browser's local workspace. */
export async function ensureBuiltinConnections(): Promise<void> {
  if (typeof window === "undefined") return;
  for (const conn of builtinConnections(window.location.origin)) {
    const existing = await localDb.connection.get(conn.id);
    if (
      !existing ||
      existing.content.url !== conn.content.url ||
      existing.content.token !== conn.content.token ||
      existing.content.driver !== conn.content.driver
    ) {
      await localDb.connection.put({
        ...conn,
        created_at: existing?.created_at || Date.now(),
        updated_at: existing?.updated_at || Date.now(),
      });
    }
  }
}
