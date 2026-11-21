<script lang="ts">
  import { onMount } from 'svelte';
  import { live } from './lib/poller.svelte';
  import Overview from './lib/Overview.svelte';
  import InterfaceTable from './lib/InterfaceTable.svelte';

  type Route = 'overview' | 'interfaces';
  const routes: { id: Route; label: string; key: string }[] = [
    { id: 'overview', label: 'Overview', key: '1' },
    { id: 'interfaces', label: 'Interfaces', key: '2' },
  ];

  function parse(): Route {
    const h = location.hash.replace(/^#\/?/, '');
    return routes.some((r) => r.id === h) ? (h as Route) : 'overview';
  }
  let route = $state<Route>(parse());
  let heading: HTMLHeadingElement | undefined = $state();
  const title = $derived(routes.find((r) => r.id === route)?.label ?? '');

  $effect(() => {
    document.title = `${title} · Edge FWSec`;
  });

  onMount(() => {
    const onHash = () => {
      route = parse();
      heading?.focus();
    };
    const onKey = (e: KeyboardEvent) => {
      const t = e.target as HTMLElement;
      if (e.metaKey || e.ctrlKey || e.altKey || t.closest('input,textarea,select,[contenteditable]')) return;
      if (e.key === 'r') void live.refresh();
      const r = routes.find((x) => x.key === e.key);
      if (r) location.hash = `#/${r.id}`;
    };
    addEventListener('hashchange', onHash);
    addEventListener('keydown', onKey);
    const stop = live.start();
    return () => {
      removeEventListener('hashchange', onHash);
      removeEventListener('keydown', onKey);
      stop();
    };
  });

  const observed = $derived(live.current ? new Date(live.current.at).toLocaleTimeString() : null);
</script>

<a class="skip" href="#main">Skip to content</a>
<div class="shell">
  <nav class="side" aria-label="Primary">
    <div class="brand"><span class="mark" aria-hidden="true"></span>edge<span class="slash">/</span>fwsec</div>
    <ul>
      {#each routes as r (r.id)}
        <li>
          <a href="#/{r.id}" aria-current={route === r.id ? 'page' : undefined}>
            <span>{r.label}</span><kbd>{r.key}</kbd>
          </a>
        </li>
      {/each}
    </ul>
    <div class="side-foot">
      <div class="mono">{live.system?.system.hostname ?? ''}</div>
      <div class="muted mono">{live.system?.version ?? ''}</div>
    </div>
  </nav>

  <main id="main">
    <header class="top">
      <h1 tabindex="-1" bind:this={heading}>{title}</h1>
      <div class="status" aria-live="polite">
        {#if live.error}
          <span class="err">Not updating: {live.error.message}</span>
        {:else if observed}
          <span class="muted">Observed {observed}{live.paused ? ' · paused' : ''}</span>
        {/if}
      </div>
      <div class="actions">
        <label class="toggle"><input type="checkbox" bind:checked={live.paused} /> Pause</label>
        <button type="button" onclick={() => live.refresh()} disabled={live.loading} title="Refresh (r)">
          {live.loading ? 'Refreshing…' : 'Refresh'}
        </button>
      </div>
    </header>

    {#if live.error && !live.current}
      <div class="banner" role="alert">
        <strong>The appliance API is unreachable.</strong>
        <p>{live.error.message} ({live.error.code}). Use <code>efwctl interfaces</code> on the local console to inspect state.</p>
      </div>
    {:else if !live.current}
      <p class="muted">Reading interface state…</p>
    {:else if route === 'overview'}
      <Overview />
    {:else}
      <section aria-label="All interfaces">
        <InterfaceTable interfaces={live.current.data.interfaces} />
        <p class="foot muted">
          Rates are derived from two consecutive kernel counter samples. “—” means the kernel did not report the value.
        </p>
      </section>
    {/if}
  </main>
</div>
