<script lang="ts">
  import { onMount } from 'svelte';
  import { api, ApiError, type HistoryEvent } from './api';

  let events = $state<HistoryEvent[] | null>(null);
  let error = $state<string | null>(null);
  const labels: Record<string, string> = {
    propose: 'stored', apply: 'applied for testing', confirm: 'confirmed', rollback: 'rolled back', recover: 'recovered',
    apply_failed: 'apply failed', restore_startup: 'restored at startup', restore_rollback: 'restored', network_rollback_failed: 'network rollback failed',
  };
  const attention = new Set(['rollback', 'recover', 'apply_failed', 'network_rollback_failed']);

  async function load() {
    try {
      const r = await api.history(300);
      events = (r.history ?? []).slice().reverse();
      error = null;
    } catch (e) {
      error = e instanceof ApiError ? e.message : String(e);
    }
  }
  onMount(load);
</script>

<section aria-labelledby="h-hist">
  <div class="section-head"><h2 id="h-hist">Change history</h2><button onclick={load}>Refresh</button></div>
  {#if error}<p class="err" role="alert">{error}</p>{/if}
  {#if events === null}
    <p class="muted">Loading…</p>
  {:else}
    <div class="scroll"><table class="grid">
      <thead><tr><th scope="col">Time</th><th scope="col">Event</th><th class="num" scope="col">Revision</th><th scope="col">Author</th><th scope="col">Result</th></tr></thead>
      <tbody>
        {#each events as e, i (i)}
          {@const failed = e.result !== 'ok' && !e.result.startsWith('testing until')}
          <tr>
            <td class="mono">{new Date(e.time).toLocaleString()}</td>
            <td class:attn={attention.has(e.action)}>{labels[e.action] ?? e.action}</td>
            <td class="num mono">{e.revision || '—'}</td>
            <td>{e.author.split(' via ')[0]}{#if e.author.includes(' via ')}<span class="muted small via">via {e.author.split(' via ')[1]}</span>{/if}</td>
            <td class:attn={failed && e.action !== 'rollback'}>{e.result}</td>
          </tr>
        {:else}<tr><td class="empty" colspan="5">No changes recorded yet.</td></tr>{/each}
      </tbody>
    </table></div>
  {/if}
</section>

<style>
  .via {
    margin-left: 6px;
  }
</style>
