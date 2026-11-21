<script lang="ts">
  import { api, ApiError } from './api';
  import { app } from './state.svelte';

  let busy = $state(false);
  let error = $state<string | null>(null);
  const t = $derived(app.status?.testing);
  const mmss = $derived.by(() => {
    const r = app.remaining ?? 0;
    return `${Math.floor(r / 60)}:${String(r % 60).padStart(2, '0')}`;
  });

  async function act(kind: 'confirm' | 'rollback') {
    if (!t) return;
    busy = true;
    error = null;
    try {
      if (kind === 'confirm') await api.confirm(t.revision);
      else await api.rollback();
      await app.refreshStatus();
      await app.loadConfig();
    } catch (e) {
      error = e instanceof ApiError ? e.message : String(e);
    } finally {
      busy = false;
    }
  }
</script>

{#if t}
  <div class="test-banner" role="status" aria-live="polite">
    <div>
      <strong>Revision {t.revision} is under test.</strong>
      It rolls back to {app.status?.confirmed ? `revision ${app.status.confirmed}` : 'the state before any configuration'} in
      <span class="mono countdown">{mmss}</span> unless confirmed.
      <span class="muted">Applied by {t.author.split(' via ')[0]}.</span>
      {#if error}<span class="err"> {error}</span>{/if}
    </div>
    <div class="row">
      <button class="primary" disabled={busy} onclick={() => act('confirm')}>Keep changes</button>
      <button disabled={busy} onclick={() => act('rollback')}>Roll back now</button>
    </div>
  </div>
{/if}
