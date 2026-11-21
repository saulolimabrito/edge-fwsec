// Application state: session, policy status (with countdown) and draft.
import { api, ApiError, setCsrf, setUnauthenticatedHandler, type PolicyStatus, type SessionInfo } from './api';
import { clone, sameConfig, type Config } from './model';

class AppState {
  session = $state<SessionInfo | null>(null);
  sessionError = $state<string | null>(null);

  status = $state<PolicyStatus | null>(null);
  statusError = $state<string | null>(null);
  nowMs = $state(Date.now());

  confirmedRevision = $state(0);
  confirmed = $state<Config | null>(null);
  draft = $state<Config | null>(null);
  loadingConfig = $state(false);

  #timers: ReturnType<typeof setInterval>[] = [];

  get authenticated(): boolean {
    return !!this.session?.authenticated;
  }

  /** Seconds left in the confirmation window, from the server deadline. */
  get remaining(): number | null {
    const t = this.status?.testing;
    if (!t) return null;
    return Math.max(0, Math.round((Date.parse(t.deadline) - this.nowMs) / 1000));
  }

  get dirty(): boolean {
    return this.draft !== null && !sameConfig(this.draft, this.confirmed);
  }

  async loadSession(): Promise<void> {
    try {
      const s = await api.session();
      this.session = s;
      setCsrf(s.csrf);
      this.sessionError = null;
    } catch (e) {
      this.sessionError = e instanceof ApiError ? e.message : String(e);
    }
  }

  setSession(s: SessionInfo): void {
    this.session = s;
    setCsrf(s.csrf);
  }

  async logout(): Promise<void> {
    try {
      await api.logout();
    } finally {
      this.reset();
      await this.loadSession();
    }
  }

  reset(): void {
    this.session = this.session ? { ...this.session, authenticated: false, csrf: undefined, user: undefined } : null;
    setCsrf(undefined);
    this.status = null;
    this.confirmed = null;
    this.draft = null;
  }

  async refreshStatus(): Promise<void> {
    try {
      const r = await api.status();
      const before = this.status;
      this.status = r.status ?? null;
      this.statusError = null;
      // A test ended (confirmed, rolled back or expired): reload the config.
      if (before?.testing && !this.status?.testing) await this.loadConfig(true);
      else if (this.status && this.status.confirmed !== this.confirmedRevision) await this.loadConfig(true);
    } catch (e) {
      this.statusError = e instanceof ApiError ? e.message : String(e);
    }
  }

  /** Loads the confirmed configuration; keeps a dirty draft unless forced. */
  async loadConfig(keepDraftIfDirty = false): Promise<void> {
    this.loadingConfig = true;
    try {
      const r = await api.config();
      const wasDirty = this.dirty;
      this.confirmedRevision = r.revision;
      this.confirmed = r.config;
      if (!keepDraftIfDirty || !wasDirty || this.draft === null) {
        this.draft = this.restoreDraft(r.revision) ?? (r.config ? clone(r.config) : null);
      }
    } finally {
      this.loadingConfig = false;
    }
  }

  discardDraft(): void {
    this.draft = this.confirmed ? clone(this.confirmed) : null;
    this.saveDraft();
  }

  // The draft survives a page reload in this tab only (sessionStorage), tied
  // to the user and to the revision it was based on. Storage may be
  // unavailable (private mode); the console works without it.
  #draftKey(): string {
    return `efw-draft:${this.session?.user ?? ''}`;
  }

  saveDraft(): void {
    try {
      if (this.dirty && this.draft) sessionStorage.setItem(this.#draftKey(), JSON.stringify({ base: this.confirmedRevision, draft: this.draft }));
      else sessionStorage.removeItem(this.#draftKey());
    } catch {
      /* storage unavailable */
    }
  }

  restoreDraft(base: number): Config | null {
    try {
      const raw = sessionStorage.getItem(this.#draftKey());
      if (!raw) return null;
      const v = JSON.parse(raw) as { base: number; draft: Config };
      return v.base === base ? v.draft : null;
    } catch {
      return null;
    }
  }

  start(): () => void {
    setUnauthenticatedHandler(() => {
      this.reset();
      void this.loadSession();
    });
    this.#timers.push(setInterval(() => (this.nowMs = Date.now()), 1000));
    this.#timers.push(
      setInterval(() => {
        if (this.authenticated && document.visibilityState === 'visible') void this.refreshStatus();
      }, 3000),
    );
    return () => this.#timers.forEach(clearInterval);
  }
}

export const app = new AppState();
