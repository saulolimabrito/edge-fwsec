<script lang="ts">
  import { app } from './state.svelte';
  import { parseList, parsePorts, portsText, type ServiceEntry } from './model';

  const cfg = $derived(app.draft);
  let netForm = $state<{ index: number | null; name: string; prefixes: string } | null>(null);
  let svcForm = $state<{ index: number | null; name: string; rows: { protocol: ServiceEntry['protocol']; ports: string }[] } | null>(null);
  let error = $state<string | null>(null);
  const ident = /^[a-z][a-z0-9_-]{0,31}$/;

  function usedBy(name: string): string[] {
    if (!cfg) return [];
    const out: string[] = [];
    for (const r of cfg.firewall.rules) if (r.source?.includes(name) || r.destination?.includes(name) || r.service === name) out.push(`rule ${r.id}`);
    for (const s of cfg.nat.source) if (s.source?.includes(name)) out.push(`source NAT ${s.id}`);
    for (const p of cfg.nat.port_forwards) if (p.allow_from?.includes(name)) out.push(`port forward ${p.id}`);
    if (cfg.admin.sources.includes(name)) out.push('console access');
    return out;
  }

  function saveNet(e: SubmitEvent) {
    e.preventDefault();
    if (!cfg || !netForm) return;
    if (!ident.test(netForm.name)) return void (error = 'Name: lowercase letters, digits, "-" or "_", starting with a letter.');
    const obj = { name: netForm.name, prefixes: parseList(netForm.prefixes) };
    if (!obj.prefixes.length) return void (error = 'Add at least one prefix.');
    if (netForm.index === null) cfg.networks = [...cfg.networks, obj];
    else cfg.networks[netForm.index] = obj;
    netForm = null;
    error = null;
  }

  function saveSvc(e: SubmitEvent) {
    e.preventDefault();
    if (!cfg || !svcForm) return;
    if (!ident.test(svcForm.name)) return void (error = 'Name: lowercase letters, digits, "-" or "_", starting with a letter.');
    try {
      const entries: ServiceEntry[] = svcForm.rows.map((r) =>
        r.protocol === 'tcp' || r.protocol === 'udp' ? { protocol: r.protocol, ports: parsePorts(r.ports) } : { protocol: r.protocol },
      );
      const obj = { name: svcForm.name, entries };
      if (svcForm.index === null) cfg.services = [...cfg.services, obj];
      else cfg.services[svcForm.index] = obj;
      svcForm = null;
      error = null;
    } catch (err) {
      error = (err as Error).message;
    }
  }

  function del(kind: 'networks' | 'services', i: number) {
    if (!cfg) return;
    const name = cfg[kind][i]?.name ?? '';
    const users = usedBy(name);
    if (users.length) return void (error = `"${name}" is used by ${users.join(', ')}.`);
    if (kind === 'networks') cfg.networks = cfg.networks.filter((_, j) => j !== i);
    else cfg.services = cfg.services.filter((_, j) => j !== i);
  }
</script>

{#if !cfg}
  <p class="note">There is no configuration yet. Use <a href="#/setup">First access</a> to create one.</p>
{:else}
  {#if error}<p class="err" role="alert">{error}</p>{/if}
  <section aria-labelledby="h-nets">
    <div class="section-head">
      <h2 id="h-nets">Network objects</h2>
      <button onclick={() => ((netForm = { index: null, name: '', prefixes: '' }), (error = null))}>Add network</button>
    </div>
    <div class="scroll"><table class="grid">
      <thead><tr><th scope="col">Name</th><th scope="col">IPv4</th><th scope="col">IPv6</th><th scope="col">Used by</th><th scope="col"><span class="sr-only">Controls</span></th></tr></thead>
      <tbody>
        {#each cfg.networks as n, i (n.name)}
          <tr>
            <td class="mono strong">{n.name}</td>
            <td class="mono">{n.prefixes.filter((p) => !p.includes(':')).join(', ') || '—'}</td>
            <td class="mono">{n.prefixes.filter((p) => p.includes(':')).join(', ') || '—'}</td>
            <td class="muted">{usedBy(n.name).join(', ') || '—'}</td>
            <td class="controls">
              <button onclick={() => ((netForm = { index: i, name: n.name, prefixes: n.prefixes.join(', ') }), (error = null))}>Edit</button>
              <button class="danger-link" onclick={() => del('networks', i)}>Delete</button>
            </td>
          </tr>
        {:else}<tr><td class="empty" colspan="5">No network objects.</td></tr>{/each}
      </tbody>
    </table></div>
    {#if netForm}
      <form class="form inline editor" onsubmit={saveNet}>
        <label>Name <input class="mono" bind:value={netForm.name} required /></label>
        <label class="grow">Prefixes (IPv4 and/or IPv6) <input class="mono" bind:value={netForm.prefixes} placeholder="192.168.10.0/24, 2001:db8:10::/64" /></label>
        <button class="primary" type="submit">Save to draft</button>
        <button type="button" onclick={() => (netForm = null)}>Cancel</button>
      </form>
    {/if}
  </section>

  <section aria-labelledby="h-svcs">
    <div class="section-head">
      <h2 id="h-svcs">Service objects</h2>
      <button onclick={() => ((svcForm = { index: null, name: '', rows: [{ protocol: 'tcp', ports: '' }] }), (error = null))}>Add service</button>
    </div>
    <div class="scroll"><table class="grid">
      <thead><tr><th scope="col">Name</th><th scope="col">Protocols and ports</th><th scope="col">Used by</th><th scope="col"><span class="sr-only">Controls</span></th></tr></thead>
      <tbody>
        {#each cfg.services as s, i (s.name)}
          <tr>
            <td class="mono strong">{s.name}</td>
            <td class="mono">{s.entries.map((e) => (e.protocol === 'tcp' || e.protocol === 'udp' ? `${e.protocol}/${portsText(e.ports)}` : e.protocol)).join('  ')}</td>
            <td class="muted">{usedBy(s.name).join(', ') || '—'}</td>
            <td class="controls">
              <button onclick={() => ((svcForm = { index: i, name: s.name, rows: s.entries.map((e) => ({ protocol: e.protocol, ports: e.ports?.length ? portsText(e.ports) : '' })) }), (error = null))}>Edit</button>
              <button class="danger-link" onclick={() => del('services', i)}>Delete</button>
            </td>
          </tr>
        {:else}<tr><td class="empty" colspan="4">No service objects.</td></tr>{/each}
      </tbody>
    </table></div>
    {#if svcForm}
      <form class="form editor" onsubmit={saveSvc}>
        <label>Name <input class="mono" bind:value={svcForm.name} required /></label>
        {#each svcForm.rows as row, k (k)}
          <div class="form inline">
            <label>Protocol
              <select bind:value={row.protocol}><option value="tcp">tcp</option><option value="udp">udp</option><option value="icmp">icmp</option><option value="icmpv6">icmpv6</option></select>
            </label>
            {#if row.protocol === 'tcp' || row.protocol === 'udp'}
              <label class="grow">Ports <input class="mono" bind:value={row.ports} placeholder="any, or 80, 443, 8000-8080" /></label>
            {/if}
            <button type="button" class="danger-link" disabled={svcForm.rows.length === 1} onclick={() => svcForm && (svcForm.rows = svcForm.rows.filter((_, j) => j !== k))}>Remove</button>
          </div>
        {/each}
        <div class="row">
          <button type="button" onclick={() => svcForm && (svcForm.rows = [...svcForm.rows, { protocol: 'udp', ports: '' }])}>Add protocol</button>
          <button class="primary" type="submit">Save to draft</button>
          <button type="button" onclick={() => (svcForm = null)}>Cancel</button>
        </div>
      </form>
    {/if}
  </section>
{/if}
