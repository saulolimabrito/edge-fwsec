// Pure formatting helpers. Null means "not reported by the kernel" and is
// rendered as an em dash, never as zero.

export const NA = '—';

export function bytes(n: number | null | undefined): string {
  if (n === null || n === undefined) return NA;
  const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB', 'PiB'];
  let v = n;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  return i === 0 ? `${v} B` : `${v.toFixed(v < 10 ? 2 : v < 100 ? 1 : 0)} ${units[i]}`;
}

export function bitrate(bitsPerSecond: number | null | undefined): string {
  if (bitsPerSecond === null || bitsPerSecond === undefined || !Number.isFinite(bitsPerSecond)) return NA;
  const units = ['bit/s', 'kbit/s', 'Mbit/s', 'Gbit/s', 'Tbit/s'];
  let v = bitsPerSecond;
  let i = 0;
  while (v >= 1000 && i < units.length - 1) {
    v /= 1000;
    i++;
  }
  return `${v.toFixed(i === 0 ? 0 : v < 10 ? 2 : 1)} ${units[i]}`;
}

export function count(n: number | null | undefined): string {
  if (n === null || n === undefined) return NA;
  return n.toLocaleString('en-US');
}

export function duration(seconds: number | null | undefined): string {
  if (seconds === null || seconds === undefined) return NA;
  const s = Math.floor(seconds);
  const d = Math.floor(s / 86400);
  const h = Math.floor((s % 86400) / 3600);
  const m = Math.floor((s % 3600) / 60);
  if (d > 0) return `${d}d ${h}h ${m}m`;
  if (h > 0) return `${h}h ${m}m`;
  return `${m}m ${s % 60}s`;
}

/** Rate between two counter samples; null when unknown or the counter reset. */
export function rate(prev: number | null | undefined, cur: number | null | undefined, dtSeconds: number): number | null {
  if (prev == null || cur == null || dtSeconds <= 0 || cur < prev) return null;
  return (cur - prev) / dtSeconds;
}

export type LinkHealth = 'up' | 'down' | 'disabled' | 'unknown';

/** An interface that is administratively up but has no carrier needs attention. */
export function health(adminUp: boolean, oper: string): LinkHealth {
  if (!adminUp) return 'disabled';
  if (oper === 'up') return 'up';
  // Loopback and some virtual devices report "unknown" while working.
  if (oper === 'unknown') return 'unknown';
  return 'down';
}
