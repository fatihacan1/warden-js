/**
 * Where the client keeps values that must survive a reload: the refresh
 * token (token mode only) and the PKCE state of a social sign-in in progress.
 *
 * Methods may be sync or async, so React Native secure stores plug in
 * directly:
 *
 * ```ts
 * import * as SecureStore from "expo-secure-store";
 * const storage = {
 *   getItem: (k) => SecureStore.getItemAsync(k),
 *   setItem: (k, v) => SecureStore.setItemAsync(k, v),
 *   removeItem: (k) => SecureStore.deleteItemAsync(k),
 * };
 * ```
 */
export interface StorageAdapter {
  getItem(key: string): string | null | undefined | Promise<string | null | undefined>;
  setItem(key: string, value: string): void | Promise<void>;
  removeItem(key: string): void | Promise<void>;
}

/** Keeps values in memory only: they are gone after a reload. */
export function memoryStorage(): StorageAdapter {
  const m = new Map<string, string>();
  return {
    getItem: (k) => m.get(k) ?? null,
    setItem: (k, v) => void m.set(k, v),
    removeItem: (k) => void m.delete(k),
  };
}

/**
 * Wraps window.localStorage or window.sessionStorage. Never fails: private
 * browsing modes that block storage fall back to memory.
 */
export function browserStorage(kind: "local" | "session" = "local"): StorageAdapter {
  const fallback = memoryStorage();
  const store = (): Storage | undefined => {
    try {
      const s = kind === "local" ? globalThis.localStorage : globalThis.sessionStorage;
      return s ?? undefined;
    } catch {
      return undefined;
    }
  };
  return {
    getItem: (k) => {
      try {
        return store()?.getItem(k) ?? fallback.getItem(k);
      } catch {
        return fallback.getItem(k);
      }
    },
    setItem: (k, v) => {
      try {
        const s = store();
        if (s) s.setItem(k, v);
        else void fallback.setItem(k, v);
      } catch {
        void fallback.setItem(k, v);
      }
    },
    removeItem: (k) => {
      try {
        store()?.removeItem(k);
      } catch {
        /* storage unavailable */
      }
      void fallback.removeItem(k);
    },
  };
}

export function isBrowser(): boolean {
  return typeof window !== "undefined" && typeof (window as { document?: unknown }).document !== "undefined";
}
