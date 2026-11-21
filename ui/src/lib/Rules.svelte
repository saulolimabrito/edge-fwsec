<script lang="ts">
  import { tick } from 'svelte';
  import { app } from './state.svelte';
  import { clone, listText, move, nextId, parseList, type Rule } from './model';

  type Dir = 'input' | 'forward';
  let editing = $state<{ index: number | null; rule: Rule; source: string; destination: string } | null>(null);
  let formError = $state<string | null>(null);

  const cfg = $derived(app.draft);
  const ifNames = $derived(cfg?.interfaces.map((i) => i.name) ?? []);
  const services = $derived(cfg?.services.map((s) => s.name) ?? []);
  const devOf = (n?: string) => cfg?.interfaces.find((i) => i.name === n)?.device;

  function rowsOf(dir: Dir) {
    return (cfg?.firewall.rules ?? []).map((r, i) => ({ r, i })).filter((x) => x.r.direction === dir);
  }

  function moveRule(dir: Dir, pos: number, delta: number) {
    if (!cfg) return;
    const rows = rowsOf(dir);
    const a = rows[pos], b = rows[pos + delta];
    if (!a || !b) return;
    // Swap positions in the full list so other directions keep their order.
    const list = cfg.firewall.rules.slice();
    list[a.i] = b.r;
    list[b.i] = a.r;
    cfg.firewall.rules = list;
    // Keep keyboard focus on the moved rule's control, not on its old row.
    void tick().then(() => {
      const sel = `button[data-rule="${a.r.id}"][data-move="${delta < 0 ? 'up' : 'down'}"]`;
      const btn = document.querySelector<HTMLButtonElement>(sel);
      (btn && !btn.disabled ? btn : document.querySelector<HTMLButtonElement>(`button[data-rule="${a.r.id}"][data-move="${delta < 0 ? 'down' : 'up'}"]`))?.focus();
    });
  }

  let idInput: HTMLInputElement | undefined = $state();
  $effect(() => {
    if (editing && idInput) {
      idInput.scrollIntoView({ block: 'center' });
      idInput.focus();
    }
  });

  function startNew(dir: Dir) {
    if (!cfg) return;
    const id = nextId(dir === 'input' ? 'in' : 'fwd', cfg.firewall.rules.map((r) => r.id));
    editing = { index: null, rule: { id, direction: dir, action: 'accept', family: 'any' }, source: '', destination: '' };
    formError = null;
  }

  function startEdit(i: number) {
    const r = cfg?.firewall.rules[i];
    if (!r) return;
    editing = { index: i, rule: clone(r), source: (r.source ?? []).join(', '), destination: (r.destination ?? []).join(', ') };
    formError = null;
  }

  function save(e: SubmitEvent) {
    e.preventDefault();
    if (!cfg || !editing) return;
    const r = editing.rule;
    if (!/^[a-z][a-z0-9_-]{0,31}$/.test(r.id)) {
      formError = 'ID: lowercase letters, digits, "-" or "_", starting with a letter (max 32).';
      return;
    }
    if (cfg.firewall.rules.some((x, i) => x.id === r.id && i !== editing!.index)) {
      formError = `ID "${r.id}" is already used.`;
      return;
    }
    r.source = parseList(editing.source);
    r.destination = parseList(editing.destination);
    if (r.direction === 'input') r.out = undefined;
    for (const k of ['in', 'out', 'service', 'description'] as const) if (!r[k]) delete r[k];
    if (editing.index === null) cfg.firewall.rules = [...cfg.firewall.rules, r];
    else cfg.firewall.rules[editing.index] = r;
    editing = null;
  }

  function remove(i: number) {
    if (!cfg) return;
    cfg.firewall.rules = cfg.firewall.rules.filter((_, j) => j !== i);
    if (editing?.index === i) editing = null;
  }

  const ifaceLabel = (n?: string) => (n ? `${n}${devOf(n) ? ` (${devOf(n)})` : ''}` : 'any');
</script>

{#if !cfg}
  <p class="note">There is no configuration yet. Use <a href="#/setup">First access</a> to create one.</p>
{:else}
  <section aria-labelledby="h-defaults">
    <h2 id="h-defaults">Default policy</h2>
    <div class="form inline">
      <label>
        Traffic to the appliance (input)
        <select bind:value={cfg.firewall.default_input}><option value="drop">drop</option><option value="reject">reject</option></select>
      </label>
      <label>
        Traffic through the appliance (forward)
        <select bind:value={cfg.firewall.default_forward}>
          <option value="drop">drop</option><option value="reject">reject</option><option value="accept">accept</option>
        </select>
      </label>
      <label class="check"><input type="checkbox" bind:checked={cfg.firewall.log_default} /> Log packets hitting the default policy (10/s max)</label>
    </div>
  </section>

  {#each [['input', 'Input — traffic to the appliance'], ['forward', 'Forward — traffic through the appliance']] as [dir, title] (dir)}
    {@const rows = rowsOf(dir as Dir)}
    <section aria-labelledby="h-{dir}">
      <div class="section-head">
        <h2 id="h-{dir}">{title}</h2>
        <button onclick={() => startNew(dir as Dir)}>Add {dir} rule</button>
      </div>
      <div class="scroll">
        <table class="grid">
          <caption class="sr-only">{title}, in evaluation order</caption>
          <thead>
            <tr>
              <th class="num" scope="col">#</th><th scope="col">Rule</th><th scope="col">In</th>
              {#if dir === 'forward'}<th scope="col">Out</th>{/if}
              <th scope="col">Family</th><th scope="col">Source</th><th scope="col">Destination</th><th scope="col">Service</th>
              <th scope="col">Action</th><th scope="col">Log</th><th scope="col"><span class="sr-only">Controls</span></th>
            </tr>
          </thead>
          <tbody>
            <tr class="implicit"><td class="num">–</td><td colspan={dir === 'forward' ? 10 : 9}>Established and related traffic accepted, invalid dropped</td></tr>
            {#if dir === 'input'}
              <tr class="implicit"><td class="num">–</td><td colspan="9">Loopback, essential ICMPv6 (ND, MLD, errors), DHCP/DHCPv6 replies on dynamic links</td></tr>
              <tr class="implicit"><td class="num">–</td><td colspan="9">Console HTTPS port {cfg.admin.port} on {listText(cfg.admin.interfaces, 'no interface')}{cfg.admin.sources.length ? ` from ${listText(cfg.admin.sources)}` : ''}</td></tr>
            {:else}
              <tr class="implicit"><td class="num">–</td><td colspan="10">ICMPv6 errors (including Packet Too Big)</td></tr>
              {#each cfg.nat.port_forwards.filter((p) => !p.disabled) as pf (pf.id)}
                <tr class="implicit"><td class="num">–</td><td colspan="10">Port forward <span class="mono">{pf.id}</span>: {pf.protocol} to {pf.target}:{pf.target_port ?? (pf.external_ports.from === pf.external_ports.to ? pf.external_ports.from : `${pf.external_ports.from}-${pf.external_ports.to}`)} from {ifaceLabel(pf.in)} — generated, edit under NAT</td></tr>
              {/each}
            {/if}
            {#each rows as { r, i }, pos (r.id)}
              <tr class:disabled={r.disabled} class:selected={editing?.index === i}>
                <td class="num mono">{pos + 1}</td>
                <td><span class="mono strong">{r.id}</span>{#if r.description}<div class="muted small">{r.description}</div>{/if}{#if r.disabled}<div class="muted small">disabled</div>{/if}</td>
                <td>{ifaceLabel(r.in)}</td>
                {#if dir === 'forward'}<td>{ifaceLabel(r.out)}</td>{/if}
                <td>{r.family ?? 'any'}</td>
                <td class="mono">{listText(r.source)}</td>
                <td class="mono">{listText(r.destination)}</td>
                <td>{r.service ?? 'any'}</td>
                <td class="action-{r.action}">{r.action}</td>
                <td>{r.log ? 'yes' : '—'}</td>
                <td class="controls">
                  <button class="icon" data-rule={r.id} data-move="up" aria-label="Move {r.id} up" disabled={pos === 0} onclick={() => moveRule(dir as Dir, pos, -1)}>↑</button>
                  <button class="icon" data-rule={r.id} data-move="down" aria-label="Move {r.id} down" disabled={pos === rows.length - 1} onclick={() => moveRule(dir as Dir, pos, 1)}>↓</button>
                  <button onclick={() => startEdit(i)}>Edit</button>
                  <button class="danger-link" onclick={() => remove(i)}>Delete</button>
                </td>
              </tr>
            {:else}
              <tr><td class="empty" colspan={dir === 'forward' ? 11 : 10}>No {dir} rules; the default policy ({dir === 'input' ? cfg.firewall.default_input : cfg.firewall.default_forward}) applies.</td></tr>
            {/each}
            <tr class="implicit"><td class="num">–</td><td colspan={dir === 'forward' ? 10 : 9}>Default policy: {dir === 'input' ? cfg.firewall.default_input : cfg.firewall.default_forward}{cfg.firewall.log_default ? ', logged' : ''}</td></tr>
          </tbody>
        </table>
      </div>
    </section>
  {/each}

  {#if editing}
    <section class="editor" aria-labelledby="h-edit">
      <h2 id="h-edit">{editing.index === null ? 'New rule' : `Edit rule ${editing.rule.id}`}</h2>
      <form class="form grid2" onsubmit={save}>
        <label>ID <input bind:this={idInput} bind:value={editing.rule.id} class="mono" required /></label>
        <label>Description <input bind:value={editing.rule.description} maxlength="200" /></label>
        <label>Direction
          <select bind:value={editing.rule.direction}><option value="input">input</option><option value="forward">forward</option></select>
        </label>
        <label>Action
          <select bind:value={editing.rule.action}><option value="accept">accept</option><option value="drop">drop</option><option value="reject">reject</option></select>
        </label>
        <label>Incoming interface
          <select bind:value={editing.rule.in}><option value={undefined}>any</option>{#each ifNames as n (n)}<option value={n}>{n}</option>{/each}</select>
        </label>
        {#if editing.rule.direction === 'forward'}
          <label>Outgoing interface
            <select bind:value={editing.rule.out}><option value={undefined}>any</option>{#each ifNames as n (n)}<option value={n}>{n}</option>{/each}</select>
          </label>
        {/if}
        <label>Family
          <select bind:value={editing.rule.family}><option value="any">IPv4 and IPv6</option><option value="ipv4">IPv4 only</option><option value="ipv6">IPv6 only</option></select>
        </label>
        <label>Service
          <select bind:value={editing.rule.service}><option value={undefined}>any</option>{#each services as n (n)}<option value={n}>{n}</option>{/each}</select>
        </label>
        <label>Source <input bind:value={editing.source} class="mono" placeholder="any — or objects / prefixes, comma separated" /></label>
        <label>Destination <input bind:value={editing.destination} class="mono" placeholder="any — or objects / prefixes, comma separated" /></label>
        <label class="check"><input type="checkbox" bind:checked={editing.rule.log} /> Log matches</label>
        <label class="check"><input type="checkbox" bind:checked={editing.rule.disabled} /> Disabled</label>
        {#if formError}<p class="err span2" role="alert">{formError}</p>{/if}
        <div class="row span2">
          <button class="primary" type="submit">Save to draft</button>
          <button type="button" onclick={() => (editing = null)}>Cancel</button>
        </div>
      </form>
    </section>
  {/if}
{/if}
