<script lang="ts">
  import { app } from './state.svelte';
  import { clone, listText, nextId, parseList, parsePorts, portsText, type PortForward, type SourceNat } from './model';

  const cfg = $derived(app.draft);
  const ifNames = $derived(cfg?.interfaces.map((i) => i.name) ?? []);
  const wan = $derived(cfg?.interfaces.find((i) => i.role === 'wan')?.name ?? '');
  let snat = $state<{ index: number | null; v: SourceNat; source: string } | null>(null);
  let pf = $state<{ index: number | null; v: PortForward; ports: string; allow: string } | null>(null);
  let error = $state<string | null>(null);
  const ids = () => [...(cfg?.nat.source.map((s) => s.id) ?? []), ...(cfg?.nat.port_forwards.map((p) => p.id) ?? []), ...(cfg?.firewall.rules.map((r) => r.id) ?? [])];

  function saveSnat(e: SubmitEvent) {
    e.preventDefault();
    if (!cfg || !snat) return;
    const v = snat.v;
    v.source = parseList(snat.source);
    if (v.mode === 'masquerade') delete v.to_address;
    if (snat.index === null) cfg.nat.source = [...cfg.nat.source, v];
    else cfg.nat.source[snat.index] = v;
    snat = null;
    error = null;
  }

  function savePf(e: SubmitEvent) {
    e.preventDefault();
    if (!cfg || !pf) return;
    try {
      const r = parsePorts(pf.ports);
      if (r.length !== 1) throw new Error('Use one port or one range for the external ports.');
      pf.v.external_ports = r[0]!;
      pf.v.allow_from = parseList(pf.allow);
      if (!pf.v.target_port) delete pf.v.target_port;
      if (!pf.v.external_address) delete pf.v.external_address;
      if (pf.index === null) cfg.nat.port_forwards = [...cfg.nat.port_forwards, pf.v];
      else cfg.nat.port_forwards[pf.index] = pf.v;
      pf = null;
      error = null;
    } catch (err) {
      error = (err as Error).message;
    }
  }
</script>

{#if !cfg}
  <p class="note">There is no configuration yet. Use <a href="#/setup">First access</a> to create one.</p>
{:else}
  {#if error}<p class="err" role="alert">{error}</p>{/if}
  <p class="note">NAT is IPv4 only in this version. IPv6 is routed; publish IPv6 services with a forward rule.</p>

  <section aria-labelledby="h-snat">
    <div class="section-head">
      <h2 id="h-snat">Source NAT (outbound)</h2>
      <button onclick={() => ((snat = { index: null, v: { id: nextId('snat', ids()), out: wan, mode: 'masquerade' }, source: '' }), (error = null))}>Add source NAT</button>
    </div>
    <div class="scroll"><table class="grid">
      <thead><tr><th class="num" scope="col">#</th><th scope="col">ID</th><th scope="col">Out</th><th scope="col">Source</th><th scope="col">Translation</th><th scope="col"><span class="sr-only">Controls</span></th></tr></thead>
      <tbody>
        {#each cfg.nat.source as s, i (s.id)}
          <tr class:disabled={s.disabled}>
            <td class="num">{i + 1}</td><td class="mono strong">{s.id}</td><td>{s.out}</td><td class="mono">{listText(s.source)}</td>
            <td>{s.mode === 'masquerade' ? 'interface address (masquerade)' : `SNAT to ${s.to_address}`}</td>
            <td class="controls">
              <button onclick={() => ((snat = { index: i, v: clone(s), source: (s.source ?? []).join(', ') }), (error = null))}>Edit</button>
              <button class="danger-link" onclick={() => cfg && (cfg.nat.source = cfg.nat.source.filter((_, j) => j !== i))}>Delete</button>
            </td>
          </tr>
        {:else}<tr><td class="empty" colspan="6">No source NAT: IPv4 leaves with its original address.</td></tr>{/each}
      </tbody>
    </table></div>
    {#if snat}
      <form class="form grid2 editor" onsubmit={saveSnat}>
        <label>ID <input class="mono" bind:value={snat.v.id} required /></label>
        <label>Outgoing interface <select bind:value={snat.v.out}>{#each ifNames as n (n)}<option value={n}>{n}</option>{/each}</select></label>
        <label>Source (IPv4 objects or prefixes) <input class="mono" bind:value={snat.source} placeholder="any" /></label>
        <label>Mode <select bind:value={snat.v.mode}><option value="masquerade">masquerade</option><option value="snat">SNAT to fixed address</option></select></label>
        {#if snat.v.mode === 'snat'}<label>Translate to <input class="mono" bind:value={snat.v.to_address} required /></label>{/if}
        <label class="check"><input type="checkbox" bind:checked={snat.v.disabled} /> Disabled</label>
        <div class="row span2"><button class="primary" type="submit">Save to draft</button><button type="button" onclick={() => (snat = null)}>Cancel</button></div>
      </form>
    {/if}
  </section>

  <section aria-labelledby="h-pf">
    <div class="section-head">
      <h2 id="h-pf">Port forwards (DNAT)</h2>
      <button onclick={() => ((pf = { index: null, v: { id: nextId('pf', ids()), in: wan, protocol: 'tcp', external_ports: { from: 8080, to: 8080 }, target: '' }, ports: '', allow: '' }), (error = null))}>Add port forward</button>
    </div>
    <div class="scroll"><table class="grid">
      <thead><tr><th scope="col">ID</th><th scope="col">In</th><th scope="col">External</th><th scope="col">Target</th><th scope="col">Allowed from</th><th scope="col">Generated forward rule</th><th scope="col"><span class="sr-only">Controls</span></th></tr></thead>
      <tbody>
        {#each cfg.nat.port_forwards as p, i (p.id)}
          <tr class:disabled={p.disabled}>
            <td class="mono strong">{p.id}{#if p.description}<div class="muted small">{p.description}</div>{/if}</td>
            <td>{p.in}</td>
            <td class="mono">{p.protocol} {p.external_address ?? '*'}:{portsText([p.external_ports])}</td>
            <td class="mono">{p.target}:{p.target_port ?? portsText([p.external_ports])}</td>
            <td class="mono">{listText(p.allow_from)}</td>
            <td class="muted">accept {p.in} → {p.target}:{p.target_port ?? portsText([p.external_ports])} (DNAT only), before your forward rules</td>
            <td class="controls">
              <button onclick={() => ((pf = { index: i, v: clone(p), ports: portsText([p.external_ports]), allow: (p.allow_from ?? []).join(', ') }), (error = null))}>Edit</button>
              <button class="danger-link" onclick={() => cfg && (cfg.nat.port_forwards = cfg.nat.port_forwards.filter((_, j) => j !== i))}>Delete</button>
            </td>
          </tr>
        {:else}<tr><td class="empty" colspan="7">No port forwards.</td></tr>{/each}
      </tbody>
    </table></div>
    {#if pf}
      <form class="form grid2 editor" onsubmit={savePf}>
        <label>ID <input class="mono" bind:value={pf.v.id} required /></label>
        <label>Description <input bind:value={pf.v.description} /></label>
        <label>Incoming interface <select bind:value={pf.v.in}>{#each ifNames as n (n)}<option value={n}>{n}</option>{/each}</select></label>
        <label>Protocol <select bind:value={pf.v.protocol}><option value="tcp">tcp</option><option value="udp">udp</option></select></label>
        <label>External ports <input class="mono" bind:value={pf.ports} required placeholder="8080 or 10000-10100" /></label>
        <label>External address (optional) <input class="mono" bind:value={pf.v.external_address} placeholder="any address of the interface" /></label>
        <label>Target IPv4 address <input class="mono" bind:value={pf.v.target} required /></label>
        <label>Target port (single external port only) <input class="mono" type="number" min="1" max="65535" bind:value={pf.v.target_port} /></label>
        <label>Allowed sources <input class="mono" bind:value={pf.allow} placeholder="any" /></label>
        <label class="check"><input type="checkbox" bind:checked={pf.v.log} /> Log</label>
        <label class="check"><input type="checkbox" bind:checked={pf.v.disabled} /> Disabled</label>
        <div class="row span2"><button class="primary" type="submit">Save to draft</button><button type="button" onclick={() => (pf = null)}>Cancel</button></div>
      </form>
    {/if}
  </section>
{/if}
