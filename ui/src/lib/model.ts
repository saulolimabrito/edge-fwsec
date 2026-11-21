// Policy model types mirroring internal/policy (schema_version 1).

export type Role = 'wan' | 'lan' | 'mgmt' | 'opt';

export interface IfaceConfig {
  name: string;
  role: Role;
  device: string;
  vlan?: { parent: string; id: number };
  ipv4: { mode: 'none' | 'static' | 'dhcp'; addresses?: string[] };
  ipv6: { mode: 'none' | 'static' | 'slaac' | 'dhcp6'; addresses?: string[] };
}

export interface Route {
  destination: string;
  gateway: string;
  interface?: string;
  metric?: number;
}

export interface NetworkObj {
  name: string;
  prefixes: string[];
}

export interface PortRange {
  from: number;
  to: number;
}

export interface ServiceEntry {
  protocol: 'tcp' | 'udp' | 'icmp' | 'icmpv6';
  ports?: PortRange[];
}

export interface ServiceObj {
  name: string;
  entries: ServiceEntry[];
}

export type Action = 'accept' | 'drop' | 'reject';

export interface Rule {
  id: string;
  description?: string;
  disabled?: boolean;
  direction: 'input' | 'forward';
  in?: string;
  out?: string;
  family?: 'any' | 'ipv4' | 'ipv6';
  source?: string[];
  destination?: string[];
  service?: string;
  action: Action;
  log?: boolean;
}

export interface SourceNat {
  id: string;
  disabled?: boolean;
  out: string;
  source?: string[];
  mode: 'masquerade' | 'snat';
  to_address?: string;
}

export interface PortForward {
  id: string;
  description?: string;
  disabled?: boolean;
  in: string;
  protocol: 'tcp' | 'udp';
  external_address?: string;
  external_ports: PortRange;
  target: string;
  target_port?: number;
  allow_from?: string[];
  log?: boolean;
}

export interface Config {
  schema_version: number;
  interfaces: IfaceConfig[];
  routes: Route[];
  networks: NetworkObj[];
  services: ServiceObj[];
  admin: { port: number; interfaces: string[]; sources: string[] };
  firewall: { default_input: 'drop' | 'reject'; default_forward: 'drop' | 'reject' | 'accept'; log_default: boolean; rules: Rule[] };
  nat: { source: SourceNat[]; port_forwards: PortForward[] };
}

export function emptyConfig(): Config {
  return {
    schema_version: 1,
    interfaces: [],
    routes: [],
    networks: [],
    services: [],
    admin: { port: 443, interfaces: [], sources: [] },
    firewall: { default_input: 'drop', default_forward: 'drop', log_default: true, rules: [] },
    nat: { source: [], port_forwards: [] },
  };
}

export function clone<T>(v: T): T {
  return JSON.parse(JSON.stringify(v)) as T;
}

/** Stable comparison used for "pending changes" (key order as produced by the server). */
export function sameConfig(a: Config | null, b: Config | null): boolean {
  return JSON.stringify(normalize(a)) === JSON.stringify(normalize(b));
}

function normalize(c: Config | null): unknown {
  if (!c) return null;
  // Drop empty optional fields so editing and clearing a field is not a change.
  return JSON.parse(
    JSON.stringify(c, (_k, v) => {
      if (v === '' || v === false || (Array.isArray(v) && v.length === 0 && _k !== 'rules' && _k !== 'interfaces')) return undefined;
      return v;
    }),
  );
}

export function portsText(rs: PortRange[] | undefined): string {
  if (!rs || rs.length === 0) return 'any';
  return rs.map((r) => (r.from === r.to ? String(r.from) : `${r.from}-${r.to}`)).join(', ');
}

/** Parses "80, 443, 8000-8080" into ranges; throws with a message on error. */
export function parsePorts(s: string): PortRange[] {
  const t = s.trim();
  if (t === '' || t === 'any') return [];
  return t.split(',').map((part) => {
    const m = /^\s*(\d+)\s*(?:-\s*(\d+))?\s*$/.exec(part);
    if (!m) throw new Error(`"${part.trim()}" is not a port or range`);
    const from = Number(m[1]);
    const to = m[2] ? Number(m[2]) : from;
    if (from < 1 || to > 65535 || from > to) throw new Error(`${part.trim()} is outside 1-65535`);
    return { from, to };
  });
}

export function listText(v: string[] | undefined, empty = 'any'): string {
  return v && v.length ? v.join(', ') : empty;
}

export function parseList(s: string): string[] {
  return s
    .split(/[\s,]+/)
    .map((x) => x.trim())
    .filter(Boolean);
}

/** Moves item at i by delta within a copy of the array. */
export function move<T>(arr: T[], i: number, delta: number): T[] {
  const j = i + delta;
  if (j < 0 || j >= arr.length) return arr;
  const out = arr.slice();
  const [x] = out.splice(i, 1);
  out.splice(j, 0, x as T);
  return out;
}

export function nextId(prefix: string, taken: string[]): string {
  for (let n = 1; ; n++) {
    const id = `${prefix}-${n}`;
    if (!taken.includes(id)) return id;
  }
}
