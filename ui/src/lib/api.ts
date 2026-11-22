// Typed client for the efw-web API. Types mirror the Go packages.
import type { Config } from './model';

export type Family = 'ipv4' | 'ipv6';

export interface Address {
  family: Family;
  cidr: string;
  scope: 'global' | 'link' | 'host';
}

export interface Counters {
  rx_bytes: number | null;
  tx_bytes: number | null;
  rx_packets: number | null;
  tx_packets: number | null;
  rx_errors: number | null;
  tx_errors: number | null;
  rx_dropped: number | null;
  tx_dropped: number | null;
}

export interface Interface {
  name: string;
  index: number;
  mac: string;
  mtu: number;
  admin_up: boolean;
  oper_state: string;
  kind: string;
  vlan_id: number | null;
  parent?: string;
  speed_mbps: number | null;
  addresses: Address[];
  counters: Counters;
}

export interface SystemInfo {
  hostname: string;
  os_name: string;
  os_version: string;
  os_id: string;
  kernel: string;
  arch: string;
  uptime_seconds: number | null;
}

export interface InterfacesResponse {
  interfaces: Interface[];
  observed_at: string;
}

export interface SystemResponse {
  system: SystemInfo;
  version: string;
  observed_at: string;
}

export interface SessionInfo {
  authenticated: boolean;
  user?: string;
  csrf?: string;
  needs_bootstrap: boolean;
  bootstrap_pending: boolean;
}

export interface Testing {
  revision: number;
  started_at: string;
  deadline: string;
  author: string;
  checkpoint?: string;
}

export interface PolicyStatus {
  confirmed: number;
  last_revision: number;
  testing: Testing | null;
  remaining_seconds: number | null;
  now: string;
}

export interface Problem {
  path: string;
  message: string;
}

export interface HistoryEvent {
  time: string;
  action: string;
  revision: number;
  author: string;
  result: string;
}

export interface AgentResponse {
  ok: boolean;
  status?: PolicyStatus;
  revision?: number;
  deadline?: string;
  diff?: string;
  ruleset?: string;
  history?: HistoryEvent[];
  config?: Config;
}

export interface TLSInfo {
  custom: boolean;
  subject: string;
  issuer: string;
  dns_names: string[] | null;
  ip_addresses: string[] | null;
  not_before: string;
  not_after: string;
  sha256: string;
}

export interface RestorePreview {
  info: { revision: number; exported_at: string; exported_by: string; app_version: string; schema_version: number; migrated_from?: number };
  config: Config;
  diff: string;
}

export class ApiError extends Error {
  constructor(
    public status: number,
    public code: string,
    message: string,
    public problems: Problem[] = [],
  ) {
    super(message);
  }
}

let csrf = '';
export function setCsrf(token: string | undefined): void {
  csrf = token ?? '';
}

/** Called on any 401 so the app can return to the login screen. */
export let onUnauthenticated: () => void = () => {};
export function setUnauthenticatedHandler(f: () => void): void {
  onUnauthenticated = f;
}

async function request<T>(method: string, path: string, body?: unknown, signal?: AbortSignal, raw = false): Promise<T> {
  const headers: Record<string, string> = { Accept: 'application/json' };
  if (method !== 'GET') {
    headers['X-CSRF-Token'] = csrf;
    if (body !== undefined && !raw) headers['Content-Type'] = 'application/json';
  }
  let res: Response;
  try {
    res = await fetch(path, {
      method,
      headers,
      body: body === undefined ? undefined : raw ? (body as BodyInit) : JSON.stringify(body),
      signal,
      credentials: 'same-origin',
    });
  } catch (e) {
    if (e instanceof DOMException && e.name === 'AbortError') throw e;
    throw new ApiError(0, 'network', 'The appliance did not respond.');
  }
  if (!res.ok) {
    let code = 'http_' + res.status;
    let message = res.statusText || 'Request failed';
    let problems: Problem[] = [];
    try {
      const b = (await res.json()) as { error?: { code: string; message: string; problems?: Problem[] } };
      if (b.error) {
        code = b.error.code;
        message = b.error.message;
        problems = b.error.problems ?? [];
      }
    } catch {
      /* non-JSON error body */
    }
    if (res.status === 401 && code === 'unauthenticated') onUnauthenticated();
    throw new ApiError(res.status, code, message, problems);
  }
  return (await res.json()) as T;
}

export const api = {
  session: () => request<SessionInfo>('GET', '/api/v1/session'),
  login: (username: string, password: string) => request<SessionInfo>('POST', '/api/v1/login', { username, password }),
  bootstrap: (token: string, username: string, password: string) =>
    request<SessionInfo>('POST', '/api/v1/bootstrap', { token, username, password }),
  logout: () => request<{ ok: boolean }>('POST', '/api/v1/logout'),
  password: (current: string, next: string) => request<SessionInfo>('POST', '/api/v1/password', { current, new: next }),

  interfaces: (s?: AbortSignal) => request<InterfacesResponse>('GET', '/api/v1/interfaces', undefined, s),
  system: (s?: AbortSignal) => request<SystemResponse>('GET', '/api/v1/system', undefined, s),

  status: (s?: AbortSignal) => request<AgentResponse>('GET', '/api/v1/policy/status', undefined, s),
  config: () => request<{ revision: number; config: Config | null }>('GET', '/api/v1/policy/config'),
  history: (limit = 200) => request<AgentResponse>('GET', `/api/v1/policy/history?limit=${limit}`),
  validate: (config: Config) => request<AgentResponse>('POST', '/api/v1/policy/validate', { config }),
  diff: (config: Config) => request<AgentResponse>('POST', '/api/v1/policy/diff', { config }),
  apply: (config: Config, base_revision: number, timeout_seconds: number, message: string, signal?: AbortSignal) =>
    request<AgentResponse>('POST', '/api/v1/policy/apply', { config, base_revision, timeout_seconds, message }, signal),
  confirm: (revision: number) => request<AgentResponse>('POST', '/api/v1/policy/confirm', { revision }),
  rollback: () => request<AgentResponse>('POST', '/api/v1/policy/rollback', {}),

  restorePreview: (file: Blob) => request<RestorePreview>('POST', '/api/v1/restore/preview', file, undefined, true),
  tls: () => request<TLSInfo>('GET', '/api/v1/tls'),
  tlsUpload: (certificate_pem: string, key_pem: string) => request<TLSInfo>('POST', '/api/v1/tls', { certificate_pem, key_pem }),
  tlsRemove: () => request<TLSInfo>('DELETE', '/api/v1/tls'),
};
