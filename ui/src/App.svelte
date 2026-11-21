<script lang="ts">
  import { onMount } from 'svelte';
  import { live } from './lib/poller.svelte';
  import { app } from './lib/state.svelte';
  import Login from './lib/Login.svelte';
  import Overview from './lib/Overview.svelte';
  import InterfaceTable from './lib/InterfaceTable.svelte';
  import Network from './lib/Network.svelte';
  import Rules from './lib/Rules.svelte';
  import Objects from './lib/Objects.svelte';
  import Nat from './lib/Nat.svelte';
  import Changes from './lib/Changes.svelte';
  import History from './lib/History.svelte';
  import System from './lib/System.svelte';
  import Setup from './lib/Setup.svelte';
  import TestBanner from './lib/TestBanner.svelte';

  type Route = 'overview' | 'interfaces' | 'network' | 'rules' | 'objects' | 'nat' | 'changes' | 'history' | 'system' | 'setup';
  const groups: { label: string; items: { id: Route; label: string; key?: string }[] }[] = [
    { label: 'Status', items: [{ id: 'overview', label: 'Overview', key: '1' }, { id: 'interfaces', label: 'Interfaces', key: '2' }] },
    {
      label: 'Configuration',
      items: [
        { id: 'network', label: 'Network', key: '3' },
        { id: 'rules', label: 'Firewall rules', key: '4' },
        { id: 'objects', label: 'Objects', key: '5' },
        { id: 'nat', label: 'NAT', key: '6' },
        { id: 'changes', label: 'Changes', key: '7' },
      ],
    },
    { label: 'Administration', items: [{ id: 'history', label: 'History', key: '8' }, { id: 'system', label: 'System', key: '9' }, { id: 'setup', label: 'First access' }] },
  ];
  const all = groups.flatMap((g) => g.items);

  function parse(): Route {
    const h = location.hash.replace(/^#\/?/, '');
    return all.some((r) => r.id === h) ? (h as Route) : 'overview';
  }
  let route = $state<Route>(parse());
  let heading: HTMLHeadingElement | undefined = $state();
  const title = $derived(all.find((r) => r.id === route)?.label ?? '');

  $effect(() => {
    document.title = app.authenticated ? `${title} · Edge FWSec` : 'Sign in · Edge FWSec';
  });

  // Load data whenever a session becomes active.
  let stopLive: (() => void) | null = null;
  $effect(() => {
    if (app.authenticated) {
      void app.refreshStatus();
      void app.loadConfig().then(() => {
        if (app.confirmedRevision === 0 && !app.draft && route === 'overview') location.hash = '#/setup';
      });
      stopLive = live.start();
    } else {
      stopLive?.();
      stopLive = null;
    }
  });

  $effect(() => {
    void JSON.stringify(app.draft);
    // Not before the configuration is loaded: an empty draft at startup
    // would erase the stored one before it can be restored.
    if (app.authenticated && app.draft !== null && !app.loadingConfig) app.saveDraft();
  });

  onMount(() => {
    void app.loadSession();
    const stop = app.start();
    const onHash = () => {
      route = parse();
      heading?.focus();
    };
    const onKey = (e: KeyboardEvent) => {
      const t = e.target as HTMLElement;
      if (!app.authenticated || e.metaKey || e.ctrlKey || e.altKey || t.closest('input,textarea,select,[contenteditable]')) return;
      if (e.key === 'r') void live.refresh();
      const r = all.find((x) => x.key === e.key);
      if (r) location.hash = `#/${r.id}`;
    };
    const onLeave = (e: BeforeUnloadEvent) => {
      if (app.dirty) e.preventDefault();
    };
    addEventListener('hashchange', onHash);
    addEventListener('keydown', onKey);
    addEventListener('beforeunload', onLeave);
    return () => {
      removeEventListener('hashchange', onHash);
      removeEventListener('keydown', onKey);
      removeEventListener('beforeunload', onLeave);
      stop();
      stopLive?.();
    };
  });

  const observed = $derived(live.current ? new Date(live.current.at).toLocaleTimeString() : null);
</script>

{#if app.session === null}
  <div class="auth"><p class="muted">{app.sessionError ? `Cannot reach the appliance: ${app.sessionError}` : 'Connecting…'}</p></div>
{:else if !app.authenticated}
  <Login />
{:else}
  <a class="skip" href="#main">Skip to content</a>
  <div class="shell">
    <nav class="side" aria-label="Primary">
      <div class="brand"><span class="mark" aria-hidden="true"></span>edge<span class="slash">/</span>fwsec</div>
      {#each groups as g (g.label)}
        <div class="nav-group">
          <div class="nav-label">{g.label}</div>
          <ul>
            {#each g.items as r (r.id)}
              <li>
                <a href="#/{r.id}" aria-current={route === r.id ? 'page' : undefined}>
                  <span>{r.label}</span>
                  {#if r.id === 'changes' && app.status?.testing}<span class="pending" title="A revision is under test">testing</span>
                  {:else if r.id === 'changes' && app.dirty}<span class="pending" title="The draft differs from the confirmed revision">draft</span>
                  {:else if r.key}<kbd>{r.key}</kbd>{/if}
                </a>
              </li>
            {/each}
          </ul>
        </div>
      {/each}
      <div class="side-foot">
        <div class="mono">{live.system?.system.hostname ?? ''}</div>
        <div class="muted mono">{live.system?.version ?? ''} · rev {app.confirmedRevision}</div>
        <div class="row"><span class="muted">{app.session.user}</span><button class="link" onclick={() => app.logout()}>Sign out</button></div>
      </div>
    </nav>

    <main id="main">
      <TestBanner />
      <header class="top">
        <h1 tabindex="-1" bind:this={heading}>{title}</h1>
        <div class="status" aria-live="polite">
          {#if live.error}
            <span class="err">Not updating: {live.error.message}</span>
          {:else if observed && (route === 'overview' || route === 'interfaces')}
            <span class="muted">Observed {observed}{live.paused ? ' · paused' : ''}</span>
          {/if}
        </div>
        {#if route === 'overview' || route === 'interfaces'}
          <div class="actions">
            <label class="toggle"><input type="checkbox" bind:checked={live.paused} /> Pause</label>
            <button type="button" onclick={() => live.refresh()} disabled={live.loading} title="Refresh (r)">{live.loading ? 'Refreshing…' : 'Refresh'}</button>
          </div>
        {/if}
      </header>

      {#if route === 'overview' || route === 'interfaces'}
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
            <p class="foot muted">Rates are derived from two consecutive kernel counter samples. “—” means the kernel did not report the value.</p>
          </section>
        {/if}
      {:else if route === 'network'}<Network />
      {:else if route === 'rules'}<Rules />
      {:else if route === 'objects'}<Objects />
      {:else if route === 'nat'}<Nat />
      {:else if route === 'changes'}<Changes />
      {:else if route === 'history'}<History />
      {:else if route === 'system'}<System />
      {:else if route === 'setup'}<Setup />
      {/if}
    </main>
  </div>
{/if}
