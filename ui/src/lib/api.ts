// Typed client for the efw-web read API. Types mirror internal/sysinfo.

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

export class ApiError extends Error {
  constructor(
    public status: number,
    public code: string,
    message: string,
  ) {
    super(message);
  }
}

async function getJSON<T>(path: string, signal?: AbortSignal): Promise<T> {
  let res: Response;
  try {
    res = await fetch(path, { headers: { Accept: 'application/json' }, signal, credentials: 'same-origin' });
  } catch (e) {
    if (e instanceof DOMException && e.name === 'AbortError') throw e;
    throw new ApiError(0, 'network', 'The appliance did not respond.');
  }
  if (!res.ok) {
    let code = 'http_' + res.status;
    let message = res.statusText || 'Request failed';
    try {
      const body = (await res.json()) as { error?: { code: string; message: string } };
      if (body.error) ({ code, message } = body.error);
    } catch {
      /* non-JSON error body */
    }
    throw new ApiError(res.status, code, message);
  }
  return (await res.json()) as T;
}

export const api = {
  interfaces: (s?: AbortSignal) => getJSON<InterfacesResponse>('/api/v1/interfaces', s),
  system: (s?: AbortSignal) => getJSON<SystemResponse>('/api/v1/system', s),
};
