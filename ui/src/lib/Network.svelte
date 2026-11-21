<script lang="ts">
  import { app } from './state.svelte';
  import { live } from './poller.svelte';
  import { clone, listText, parseList, type IfaceConfig, type Route } from './model';

  const cfg = $derived(app.draft);
  const kernel = $derived(live.current?.data.interfaces.filter((i) => i.kind !== 'loopback') ?? []);
  let ifForm = $state<{ index: number | null; v: IfaceConfig; v4: string; v6: string; isVlan: boolean } | null>(null);
  let rtForm = $state<{ index: number | null; v: Route } | null>(null);
  let error = $state<string | null>(null);

  function newIface() {
    ifForm = { index: null, v: { name: '', role: 'opt', device: '', ipv4: { mode: 'static' }, ipv6: { mode: 'none' } }, v4: '', v6: '', isVlan: false };
    error = null;
  }
  function editIface(i: number) {
    const v = cfg?.interfaces[i];
    if (!v) return;
    ifForm = { index: i, v: clone(v), v4: (v.ipv4.addresses ?? []).join(', '), v6: (v.ipv6.addresses ?? []).join(', '), isVlan: !!v.vlan };
    error = null;
  }
  function saveIface(e: SubmitEvent) {
    e.preventDefault();
    if (!cfg || !ifForm) return;
    const v = ifForm.v;
    if (!/^[a-z][a-z0-9_-]{0,31}$/.test(v.name)) return void (error = 'Name: lowercase letters, digits, "-" or "_", starting with a letter.');
    if (ifForm.isVlan) {
      v.vlan = v.vlan ?? { parent: '', id: 1 };
      if (!v.device) v.device = `${v.vlan.parent}.${v.vlan.id}`;
    } else delete v.vlan;
    v.ipv4.addresses = v.ipv4.mode === 'static' ? parseList(ifForm.v4) : undefined;
    v.ipv6.addresses = v.ipv6.mode === 'static' ? parseList(ifForm.v6) : undefined;
    const old = ifForm.index === null ? null : cfg.interfaces[ifForm.index];
    if (ifForm.index === null) cfg.interfaces = [...cfg.interfaces, v];
    else cfg.interfaces[ifForm.index] = v;
    if (old && old.name !== v.name) renameRefs(old.name, v.name);
    ifForm = null;
    error = null;
  }
  function renameRefs(from: string, to: string) {
    if (!cfg) return;
    for (const r of cfg.firewall.rules) {
      if (r.in === from) r.in = to;
      if (r.out === from) r.out = to;
    }
    for (const s of cfg.nat.source) if (s.out === from) s.out = to;
    for (const p of cfg.nat.port_forwards) if (p.in === from) p.in = to;
    for (const r of cfg.routes) if (r.interface === from) r.interface = to;
    cfg.admin.interfaces = cfg.admin.interfaces.map((n) => (n === from ? to : n));
  }
  function delIface(i: number) {
    if (!cfg) return;
    const n = cfg.interfaces[i]?.name;
    const used = cfg.firewall.rules.some((r) => r.in === n || r.out === n) || cfg.nat.source.some((s) => s.out === n) || cfg.nat.port_forwards.some((p) => p.in === n) || cfg.admin.interfaces.includes(n ?? '');
    if (used) return void (error = `Interface "${n}" is referenced by rules, NAT or console access.`);
    cfg.interfaces = cfg.interfaces.filter((_, j) => j !== i);
  }
  function saveRoute(e: SubmitEvent) {
    e.preventDefault();
    if (!cfg || !rtForm) return;
    const v = rtForm.v;
    if (!v.interface) delete v.interface;
    if (!v.metric) delete v.metric;
    if (rtForm.index === null) cfg.routes = [...cfg.routes, v];
    else cfg.routes[rtForm.index] = v;
    rtForm = null;
  }
  const kernelState = (dev: string) => kernel.find((k) => k.name === dev);
</script>

{#if !cfg}
  <p class="note">There is no configuration yet. Use <a href="#/setup">First access</a> to create one.</p>
{:else}
  {#if error}<p class="err" role="alert">{error}</p>{/if}
  <section aria-labelledby="h-ifc">
    <div class="section-head">
      <h2 id="h-ifc">Interfaces and VLANs</h2>
      <button onclick={newIface}>Add interface or VLAN</button>
    </div>
    <div class="scroll"><table class="grid">
      <thead><tr><th scope="col">Name</th><th scope="col">Role</th><th scope="col">Device</th><th scope="col">IPv4</th><th scope="col">IPv6</th><th scope="col">Kernel now</th><th scope="col"><span class="sr-only">Controls</span></th></tr></thead>
      <tbody>
        {#each cfg.interfaces as it, i (it.name + i)}
          {@const k = kernelState(it.device)}
          <tr>
            <td class="mono strong">{it.name}</td>
            <td>{it.role}{cfg.admin.interfaces.includes(it.name) ? ' · console' : ''}</td>
            <td class="mono">{it.device}{#if it.vlan}<span class="muted"> vid {it.vlan.id} on {it.vlan.parent}</span>{/if}</td>
            <td class="mono">{it.ipv4.mode === 'static' ? listText(it.ipv4.addresses) : it.ipv4.mode}</td>
            <td class="mono">{it.ipv6.mode === 'static' ? listText(it.ipv6.addresses) : it.ipv6.mode}</td>
            <td>{#if k}{k.oper_state}{:else}<span class="attn">device not present</span>{/if}</td>
            <td class="controls"><button onclick={() => editIface(i)}>Edit</button><button class="danger-link" onclick={() => delIface(i)}>Delete</button></td>
          </tr>
        {:else}<tr><td class="empty" colspan="7">No interfaces configured.</td></tr>{/each}
      </tbody>
    </table></div>
    {#if ifForm}
      <form class="form grid2 editor" onsubmit={saveIface}>
        <label>Name <input class="mono" bind:value={ifForm.v.name} required placeholder="lan" /></label>
        <label>Role <select bind:value={ifForm.v.role}><option value="wan">WAN</option><option value="lan">LAN</option><option value="mgmt">management</option><option value="opt">other</option></select></label>
        <label class="check span2"><input type="checkbox" bind:checked={ifForm.isVlan} /> 802.1Q VLAN on a trunk</label>
        {#if ifForm.isVlan}
          {@const vl = (ifForm.v.vlan ??= { parent: '', id: 1 })}
          <label>Parent device <select bind:value={vl.parent}>{#each kernel.filter((k) => k.kind !== 'vlan') as k (k.name)}<option value={k.name}>{k.name}</option>{/each}</select></label>
          <label>VLAN ID <input type="number" min="1" max="4094" bind:value={vl.id} required /></label>
          <label>Device name <input class="mono" bind:value={ifForm.v.device} placeholder="{vl.parent}.{vl.id}" /></label>
        {:else}
          <label>Device
            <select bind:value={ifForm.v.device} required>
              {#each kernel.filter((k) => k.kind !== 'vlan') as k (k.name)}<option value={k.name}>{k.name} — {k.kind}, {k.oper_state}{k.mac ? `, ${k.mac}` : ''}</option>{/each}
            </select>
          </label>
        {/if}
        <label>IPv4 <select bind:value={ifForm.v.ipv4.mode}><option value="static">static</option><option value="dhcp">DHCP client</option><option value="none">none</option></select></label>
        {#if ifForm.v.ipv4.mode === 'static'}<label>IPv4 addresses <input class="mono" bind:value={ifForm.v4} placeholder="192.168.10.1/24" /></label>{/if}
        <label>IPv6 <select bind:value={ifForm.v.ipv6.mode}><option value="static">static</option><option value="slaac">SLAAC</option><option value="dhcp6">DHCPv6 client</option><option value="none">none (disabled)</option></select></label>
        {#if ifForm.v.ipv6.mode === 'static'}<label>IPv6 addresses <input class="mono" bind:value={ifForm.v6} placeholder="2001:db8:10::1/64" /></label>{/if}
        <div class="row span2"><button class="primary" type="submit">Save to draft</button><button type="button" onclick={() => (ifForm = null)}>Cancel</button></div>
      </form>
    {/if}
  </section>

  <section aria-labelledby="h-routes">
    <div class="section-head">
      <h2 id="h-routes">Static routes</h2>
      <button onclick={() => (rtForm = { index: null, v: { destination: '', gateway: '' } })}>Add route</button>
    </div>
    <div class="scroll"><table class="grid">
      <thead><tr><th scope="col">Destination</th><th scope="col">Gateway</th><th scope="col">Interface</th><th class="num" scope="col">Metric</th><th scope="col"><span class="sr-only">Controls</span></th></tr></thead>
      <tbody>
        {#each cfg.routes as r, i (i)}
          <tr>
            <td class="mono">{r.destination}{r.destination === '0.0.0.0/0' || r.destination === '::/0' ? ' (default)' : ''}</td>
            <td class="mono">{r.gateway}</td><td>{r.interface ?? 'by gateway'}</td><td class="num">{r.metric ?? '—'}</td>
            <td class="controls"><button onclick={() => (rtForm = { index: i, v: clone(r) })}>Edit</button><button class="danger-link" onclick={() => cfg && (cfg.routes = cfg.routes.filter((_, j) => j !== i))}>Delete</button></td>
          </tr>
        {:else}<tr><td class="empty" colspan="5">No static routes.</td></tr>{/each}
      </tbody>
    </table></div>
    {#if rtForm}
      <form class="form inline editor" onsubmit={saveRoute}>
        <label>Destination <input class="mono" bind:value={rtForm.v.destination} required placeholder="0.0.0.0/0" /></label>
        <label>Gateway <input class="mono" bind:value={rtForm.v.gateway} required /></label>
        <label>Interface <select bind:value={rtForm.v.interface}><option value={undefined}>by gateway</option>{#each cfg.interfaces as it (it.name)}<option value={it.name}>{it.name}</option>{/each}</select></label>
        <label>Metric <input type="number" min="0" bind:value={rtForm.v.metric} /></label>
        <button class="primary" type="submit">Save to draft</button><button type="button" onclick={() => (rtForm = null)}>Cancel</button>
      </form>
    {/if}
  </section>

  <section aria-labelledby="h-console">
    <h2 id="h-console">Console access</h2>
    <div class="form inline">
      <label>HTTPS port <input type="number" min="1" max="65535" bind:value={cfg.admin.port} /></label>
      <fieldset>
        <legend>Interfaces that serve the console</legend>
        {#each cfg.interfaces.filter((i) => i.role !== 'wan') as it (it.name)}
          <label class="check">
            <input type="checkbox" checked={cfg.admin.interfaces.includes(it.name)}
              onchange={(e) => cfg && (cfg.admin.interfaces = (e.currentTarget as HTMLInputElement).checked ? [...cfg.admin.interfaces, it.name] : cfg.admin.interfaces.filter((n) => n !== it.name))} />
            {it.name}
          </label>
        {/each}
      </fieldset>
      <label class="grow">Allowed sources <input class="mono" value={cfg.admin.sources.join(', ')} onchange={(e) => cfg && (cfg.admin.sources = parseList((e.currentTarget as HTMLInputElement).value))} placeholder="any host on those interfaces" /></label>
    </div>
    <p class="hint">The WAN can never serve the console in this version.</p>
  </section>
{/if}
