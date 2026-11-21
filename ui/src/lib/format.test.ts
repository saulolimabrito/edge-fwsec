import { describe, expect, it } from 'vitest';
import { bitrate, bytes, count, duration, health, NA, rate } from './format';

describe('format', () => {
  it('never renders missing values as zero', () => {
    expect(bytes(null)).toBe(NA);
    expect(count(undefined)).toBe(NA);
    expect(bitrate(null)).toBe(NA);
    expect(duration(null)).toBe(NA);
  });
  it('formats binary byte units', () => {
    expect(bytes(0)).toBe('0 B');
    expect(bytes(1536)).toBe('1.50 KiB');
    expect(bytes(5 * 1024 ** 3)).toBe('5.00 GiB');
  });
  it('formats decimal bit rates', () => {
    expect(bitrate(950)).toBe('950 bit/s');
    expect(bitrate(12_500_000)).toBe('12.5 Mbit/s');
  });
  it('computes rates and rejects counter resets', () => {
    expect(rate(100, 300, 2)).toBe(100);
    expect(rate(300, 100, 2)).toBeNull();
    expect(rate(null, 100, 2)).toBeNull();
    expect(rate(1, 2, 0)).toBeNull();
  });
  it('classifies link health', () => {
    expect(health(false, 'down')).toBe('disabled');
    expect(health(true, 'up')).toBe('up');
    expect(health(true, 'down')).toBe('down');
    expect(health(true, 'lowerlayerdown')).toBe('down');
    expect(health(true, 'unknown')).toBe('unknown');
  });
  it('formats uptime', () => {
    expect(duration(59)).toBe('0m 59s');
    expect(duration(3 * 86400 + 4 * 3600 + 5 * 60)).toBe('3d 4h 5m');
  });
});
