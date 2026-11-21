<script lang="ts">
  import type { Interface } from './api';
  import { bitrate, bytes, count, NA, rate } from './format';
  import StatePill from './StatePill.svelte';
  import { live } from './poller.svelte';

  let { interfaces, compact = false }: { interfaces: Interface[]; compact?: boolean } = $props();

  const prevByName = $derived(new Map((live.previous?.data.interfaces ?? []).map((i) => [i.name, i])));
  const dt = $derived(live.previous && live.current ? (live.current.at - live.previous.at) / 1000 : 0);

  function bps(it: Interface, dir: 'rx' | 'tx'): string {
    const p = prevByName.get(it.name);
    const key = dir === 'rx' ? 'rx_bytes' : 'tx_bytes';
    const r = rate(p?.counters[key], it.counters[key], dt);
    return r === null ? NA : bitrate(r * 8);
  }
  function v4(it: Interface) {
    return it.addresses.filter((a) => a.family === 'ipv4');
  }
  function v6(it: Interface) {
    return it.addresses.filter((a) => a.family === 'ipv6');
  }
  function errs(it: Interface): number | null {
    const c = it.counters;
    const parts = [c.rx_errors, c.tx_errors, c.rx_dropped, c.tx_dropped];
    if (parts.every((x) => x === null)) return null;
    return parts.reduce<number>((a, b) => a + (b ?? 0), 0);
  }
</script>

<div class="scroll" role="region" aria-label="Interfaces" tabindex="-1">
  <table class="grid">
    <thead>
      <tr>
        <th class="num" scope="col">#</th>
        <th scope="col">Interface</th>
        <th scope="col">Kind</th>
        <th scope="col">State</th>
        <th scope="col">IPv4</th>
        <th scope="col">IPv6</th>
        {#if !compact}
          <th class="num" scope="col">MTU</th>
          <th scope="col">MAC</th>
        {/if}
        <th class="num" scope="col">RX rate</th>
        <th class="num" scope="col">TX rate</th>
        {#if !compact}
          <th class="num" scope="col">RX total</th>
          <th class="num" scope="col">TX total</th>
          <th class="num" scope="col" title="rx/tx errors + drops">Err+drop</th>
        {/if}
      </tr>
    </thead>
    <tbody>
      {#each interfaces as it (it.name)}
        {@const e = errs(it)}
        <tr>
          <td class="num muted">{it.index}</td>
          <td class="mono strong">{it.name}</td>
          <td>
            {it.kind}{#if it.vlan_id !== null}<span class="muted sub">vid {it.vlan_id} on {it.parent}</span>{/if}
          </td>
          <td><StatePill adminUp={it.admin_up} oper={it.oper_state} /></td>
          <td class="mono addrs">
            {#each v4(it) as a (a.cidr)}<div>{a.cidr}</div>{:else}<span class="muted">{NA}</span>{/each}
          </td>
          <td class="mono addrs">
            {#each v6(it) as a (a.cidr)}<div>{a.cidr}{#if a.scope === 'link'}<span class="muted sub">link</span>{/if}</div>{:else}<span class="muted">{NA}</span>{/each}
          </td>
          {#if !compact}
            <td class="num mono">{it.mtu}</td>
            <td class="mono muted">{it.mac || NA}</td>
          {/if}
          <td class="num mono">{bps(it, 'rx')}</td>
          <td class="num mono">{bps(it, 'tx')}</td>
          {#if !compact}
            <td class="num mono">{bytes(it.counters.rx_bytes)}</td>
            <td class="num mono">{bytes(it.counters.tx_bytes)}</td>
            <td class="num mono" class:attn={e !== null && e > 0}>{count(e)}</td>
          {/if}
        </tr>
      {:else}
        <tr><td class="empty" colspan="13">The kernel reported no interfaces.</td></tr>
      {/each}
    </tbody>
  </table>
</div>

<style>
  .addrs div + div {
    margin-top: 2px;
  }
  .sub {
    margin-left: 6px;
  }
  .attn {
    color: var(--warn-fg);
    font-weight: 600;
  }
</style>
