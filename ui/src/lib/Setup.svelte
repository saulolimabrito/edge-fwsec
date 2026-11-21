<script lang="ts">
  import { app } from './state.svelte';
  import { live } from './poller.svelte';
  import { emptyConfig, type Config } from './model';

  const devices = $derived(live.current?.data.interfaces.filter((i) => i.kind !== 'loopback' && i.kind !== 'vlan') ?? []);
  let wan = $state({ device: '', v4: 'dhcp' as 'dhcp' | 'static', addr: '', gw: '', v6: 'slaac' as 'slaac' | 'dhcp6' | 'none' });
  let lan = $state({ device: '', addr: '192.168.1.1/24', v6: '' });
  let mgmt = $state({ separate: true, device: '', addr: '10.99.0.1/24' });
  let error = $state<string | null>(null);

  function build(e: SubmitEvent) {
    e.preventDefault();
    error = null;
    const used = [wan.device, lan.device, mgmt.separate ? mgmt.device : ''].filter(Boolean);
    if (!wan.device || !lan.device || (mgmt.separate && !mgmt.device)) return void (error = 'Choose a device for every role.');
    if (new Set(used).size !== used.length) return void (error = 'Each role needs its own device.');
    const c: Config = emptyConfig();
    c.interfaces.push({ name: 'wan', role: 'wan', device: wan.device,
      ipv4: wan.v4 === 'dhcp' ? { mode: 'dhcp' } : { mode: 'static', addresses: [wan.addr] },
      ipv6: { mode: wan.v6 } });
    c.interfaces.push({ name: 'lan', role: 'lan', device: lan.device, ipv4: { mode: 'static', addresses: [lan.addr] },
      ipv6: lan.v6 ? { mode: 'static', addresses: [lan.v6] } : { mode: 'none' } });
    if (mgmt.separate) c.interfaces.push({ name: 'mgmt', role: 'mgmt', device: mgmt.device, ipv4: { mode: 'static', addresses: [mgmt.addr] }, ipv6: { mode: 'none' } });
    if (wan.v4 === 'static' && wan.gw) c.routes.push({ destination: '0.0.0.0/0', gateway: wan.gw, interface: 'wan' });
    c.admin.interfaces = [mgmt.separate ? 'mgmt' : 'lan'];
    const lanNet = lan.addr.replace(/\.\d+\//, '.0/');
    c.networks.push({ name: 'lan_net', prefixes: [lanNet, ...(lan.v6 ? [lan.v6.replace(/::[0-9a-f]*\//i, '::/')] : [])] });
    c.services.push({ name: 'ping', entries: [{ protocol: 'icmp' }, { protocol: 'icmpv6' }] });
    c.firewall.rules.push(
      { id: 'lan-ping-fw', direction: 'input', in: 'lan', service: 'ping', action: 'accept' },
      { id: 'lan-out', description: 'LAN to the internet', direction: 'forward', in: 'lan', out: 'wan', source: ['lan_net'], action: 'accept' },
    );
    c.nat.source.push({ id: 'lan-masq', out: 'wan', source: ['lan_net'], mode: 'masquerade' });
    app.draft = c;
    location.hash = '#/changes';
  }
</script>

<section aria-labelledby="h-setup">
  <h2 id="h-setup">First access</h2>
  <p class="note">
    {#if app.confirmedRevision > 0}
      A configuration is already confirmed (revision {app.confirmedRevision}). Generating a new one replaces the draft; nothing changes until you apply and confirm it.
    {:else}
      No configuration has been applied. Choose the devices for each role; the result goes to <em>Changes</em> for review and is applied with a confirmation window. Existing addresses stay untouched until then.
    {/if}
  </p>
  <form class="form grid2" onsubmit={build}>
    <fieldset class="span2"><legend>WAN</legend>
      <div class="form grid2">
        <label>Device <select bind:value={wan.device} required><option value="">choose…</option>{#each devices as d (d.name)}<option value={d.name}>{d.name} — {d.oper_state}{d.addresses.length ? `, ${d.addresses.map((a) => a.cidr).join(' ')}` : ''}</option>{/each}</select></label>
        <label>IPv4 <select bind:value={wan.v4}><option value="dhcp">DHCP client</option><option value="static">static</option></select></label>
        {#if wan.v4 === 'static'}
          <label>Address <input class="mono" bind:value={wan.addr} required placeholder="203.0.113.2/24" /></label>
          <label>Gateway <input class="mono" bind:value={wan.gw} required placeholder="203.0.113.1" /></label>
        {/if}
        <label>IPv6 <select bind:value={wan.v6}><option value="slaac">SLAAC</option><option value="dhcp6">DHCPv6 client</option><option value="none">none</option></select></label>
      </div>
    </fieldset>
    <fieldset class="span2"><legend>LAN</legend>
      <div class="form grid2">
        <label>Device <select bind:value={lan.device} required><option value="">choose…</option>{#each devices as d (d.name)}<option value={d.name}>{d.name} — {d.oper_state}</option>{/each}</select></label>
        <label>IPv4 address <input class="mono" bind:value={lan.addr} required /></label>
        <label>IPv6 address (optional) <input class="mono" bind:value={lan.v6} placeholder="2001:db8:10::1/64" /></label>
      </div>
    </fieldset>
    <fieldset class="span2"><legend>Management</legend>
      <label class="check"><input type="checkbox" bind:checked={mgmt.separate} /> Dedicated management interface (recommended)</label>
      {#if mgmt.separate}
        <div class="form grid2">
          <label>Device <select bind:value={mgmt.device} required><option value="">choose…</option>{#each devices as d (d.name)}<option value={d.name}>{d.name} — {d.oper_state}</option>{/each}</select></label>
          <label>IPv4 address <input class="mono" bind:value={mgmt.addr} required /></label>
        </div>
      {:else}
        <p class="hint">The console will be served on the LAN interface.</p>
      {/if}
    </fieldset>
    {#if error}<p class="err span2" role="alert">{error}</p>{/if}
    <div class="row span2"><button class="primary" type="submit">Generate configuration and review</button></div>
  </form>
</section>
