<script lang="ts">
  import { live } from './poller.svelte';
  import { duration, health, NA } from './format';
  import InterfaceTable from './InterfaceTable.svelte';
  import { app } from './state.svelte';
  import { api, type HistoryEvent } from './api';

  let last = $state<HistoryEvent | null>(null);
  $effect(() => {
    void app.status?.confirmed;
    void app.status?.testing;
    api.history(20).then((r) => {
      const ev = (r.history ?? []).filter((e) => ['confirm', 'rollback', 'recover', 'apply', 'apply_failed'].includes(e.action));
      last = ev.at(-1) ?? null;
    }, () => {});
  });

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
  {#if app.statusError}
    <p class="err">Policy service unreachable: {app.statusError}. Use <code>efwctl status</code> on the local console.</p>
  {:else if app.status}
    <dl class="facts">
      <div><dt>Confirmed revision</dt><dd>{app.status.confirmed || 'none yet'}</dd></div>
      <div><dt>Under test</dt><dd>{app.status.testing ? `revision ${app.status.testing.revision}` : 'nothing'}</dd></div>
      <div><dt>Draft</dt><dd>{app.dirty ? 'differs from the confirmed revision' : 'no pending edits'}</dd></div>
      <div>
        <dt>Last change</dt>
        <dd>{#if last}{last.action} of revision {last.revision} by {last.author.split(' via ')[0]}, {new Date(last.time).toLocaleString()}{:else}—{/if}</dd>
      </div>
    </dl>
    {#if app.status.confirmed === 0}<p class="note">No configuration is applied yet. Start with <a href="#/setup">First access</a>.</p>{/if}
  {/if}
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
