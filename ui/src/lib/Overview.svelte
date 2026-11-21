<script lang="ts">
  import { live } from './poller.svelte';
  import { duration, health, NA } from './format';
  import InterfaceTable from './InterfaceTable.svelte';

  const sys = $derived(live.system?.system);
  const ifs = $derived((live.current?.data.interfaces ?? []).filter((i) => i.kind !== 'loopback'));
  const down = $derived(ifs.filter((i) => health(i.admin_up, i.oper_state) === 'down'));
</script>

<section aria-labelledby="h-host">
  <h2 id="h-host">Appliance</h2>
  <dl class="facts">
    <div><dt>Hostname</dt><dd class="mono">{sys?.hostname || NA}</dd></div>
    <div><dt>Operating system</dt><dd>{sys?.os_name || NA}</dd></div>
    <div><dt>Kernel</dt><dd class="mono">{sys?.kernel || NA} <span class="muted">{sys?.arch}</span></dd></div>
    <div><dt>Uptime</dt><dd>{duration(sys?.uptime_seconds)}</dd></div>
    <div><dt>Edge FWSec</dt><dd class="mono">{live.system?.version ?? NA}</dd></div>
    <div>
      <dt>Links</dt>
      <dd>
        {ifs.length - down.length} of {ifs.length} usable
        {#if down.length}<span class="attn"> · {down.map((d) => d.name).join(', ')} without link</span>{/if}
      </dd>
    </div>
  </dl>
</section>

<section aria-labelledby="h-policy">
  <h2 id="h-policy">Policy</h2>
  <p class="note">
    No policy revision has been applied. The policy engine (rules, NAT, apply and rollback) is not part of
    this build; this console is read-only.
  </p>
</section>

<section aria-labelledby="h-ifs">
  <div class="section-head">
    <h2 id="h-ifs">Interfaces</h2>
    <a href="#/interfaces">All details</a>
  </div>
  <InterfaceTable interfaces={ifs} compact />
</section>

<style>
  .facts {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(220px, 1fr));
    gap: 14px 32px;
    margin: 0;
  }
  dt {
    color: var(--fg-muted);
    font-size: 12px;
    margin-bottom: 2px;
  }
  dd {
    margin: 0;
  }
  .attn {
    color: var(--warn-fg);
    font-weight: 600;
  }
</style>
