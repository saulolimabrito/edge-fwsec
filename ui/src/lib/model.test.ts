import { describe, expect, it } from 'vitest';
import { emptyConfig, move, nextId, parseList, parsePorts, portsText, sameConfig } from './model';

describe('model helpers', () => {
  it('parses and prints ports', () => {
    expect(parsePorts('80, 443,8000-8080')).toEqual([
      { from: 80, to: 80 },
      { from: 443, to: 443 },
      { from: 8000, to: 8080 },
    ]);
    expect(parsePorts('any')).toEqual([]);
    expect(() => parsePorts('70000')).toThrow();
    expect(() => parsePorts('90-80')).toThrow();
    expect(() => parsePorts('http')).toThrow();
    expect(portsText([{ from: 22, to: 22 }, { from: 1000, to: 2000 }])).toBe('22, 1000-2000');
  });
  it('moves rules without mutating', () => {
    const a = ['a', 'b', 'c'];
    expect(move(a, 0, 1)).toEqual(['b', 'a', 'c']);
    expect(move(a, 0, -1)).toBe(a);
    expect(a).toEqual(['a', 'b', 'c']);
  });
  it('detects pending changes ignoring cleared optionals', () => {
    const a = emptyConfig();
    const b = emptyConfig();
    expect(sameConfig(a, b)).toBe(true);
    b.firewall.rules.push({ id: 'r', direction: 'input', action: 'accept', source: [], log: false });
    expect(sameConfig(a, b)).toBe(false);
    a.firewall.rules.push({ id: 'r', direction: 'input', action: 'accept' });
    expect(sameConfig(a, b)).toBe(true);
  });
  it('generates ids and lists', () => {
    expect(nextId('rule', ['rule-1', 'rule-2'])).toBe('rule-3');
    expect(parseList(' lan_net, 10.0.0.0/8  2001:db8::/32')).toEqual(['lan_net', '10.0.0.0/8', '2001:db8::/32']);
  });
});
