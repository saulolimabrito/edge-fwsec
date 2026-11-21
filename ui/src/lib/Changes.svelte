<script lang="ts">
  import { api, ApiError, type Problem } from './api';
  import { app } from './state.svelte';
  import Problems from './Problems.svelte';

  let diff = $state<string | null>(null);
  let problems = $state<Problem[]>([]);
  let message = $state<string | null>(null);
  let busy = $state(false);
  let timeout = $state(120);
  let note = $state('');

  const mgmtChanged = $derived.by(() => {
    const a = app.confirmed, b = app.draft;
    if (!a || !b) return false;
    const pick = (c: typeof a) =>
      JSON.stringify(c.admin) +
      JSON.stringify(c.interfaces.filter((i) => c.admin.interfaces.includes(i.name))) +
      JSON.stringify(c.routes);
    return pick(a) !== pick(b);
  });

  async function review() {
    if (!app.draft) return;
    busy = true;
    problems = [];
    message = null;
    try {
      const r = await api.diff(app.draft);
      diff = r.diff ?? '';
    } catch (e) {
      diff = null;
      if (e instanceof ApiError) {
        message = e.message;
        problems = e.problems;
      } else message = String(e);
    } finally {
      busy = false;
    }
  }

  async function apply() {
    if (!app.draft) return;
    busy = true;
    problems = [];
    message = null;
    try {
      await api.apply(app.draft, app.confirmedRevision, timeout, note);
      note = '';
      await app.refreshStatus();
    } catch (e) {
      if (e instanceof ApiError) {
        message = e.message;
        problems = e.problems;
        if (e.code === 'conflict') message = 'Another change was confirmed meanwhile. Review the new configuration and redo your edits.';
      } else message = String(e);
    } finally {
      busy = false;
    }
  }

  $effect(() => {
    // Re-review whenever the draft changes while on this page.
    void JSON.stringify(app.draft);
    diff = null;
  });

  function lineClass(l: string) {
    return l.startsWith('+') ? 'add' : l.startsWith('-') ? 'del' : l.startsWith('@@') ? 'gap' : '';
  }
</script>

<section aria-labelledby="h-pending">
  <h2 id="h-pending">Pending changes</h2>
  {#if app.status?.testing}
    <p class="note">A revision is under test. Keep or roll it back before applying another change.</p>
  {:else if !app.dirty}
    <p class="note">The draft matches confirmed revision {app.confirmedRevision}. Edit network, rules, objects or NAT to prepare a change.</p>
  {:else}
    <p class="note">The draft differs from confirmed revision {app.confirmedRevision}.</p>
    <div class="row">
      <button onclick={review} disabled={busy}>Validate and show diff</button>
      <button onclick={() => app.discardDraft()} disabled={busy}>Discard draft</button>
    </div>
  {/if}
  <Problems {problems} {message} />
</section>

{#if diff !== null && app.dirty && !app.status?.testing}
  <section aria-labelledby="h-diff">
    <h2 id="h-diff">Ruleset diff against revision {app.confirmedRevision}</h2>
    {#if diff === ''}
      <p class="note">The generated ruleset is unchanged (only metadata or network settings differ).</p>
    {:else}
      <!-- Scrollable content must be reachable by keyboard (WCAG 2.1.1). -->
      <!-- svelte-ignore a11y_no_noninteractive_tabindex -->
      <pre class="diff" tabindex="0" role="region" aria-label="Ruleset diff">{#each diff.split('\n') as l, i (i)}<span class={lineClass(l)}>{l}
</span>{/each}</pre>
    {/if}

    {#if mgmtChanged}
      <div class="warn-box" role="note">
        <strong>This change touches management access.</strong>
        If the address, VLAN or route you are using changes, this page will lose its connection. Reconnect to the new
        management address within the confirmation window, sign in again and choose <em>Keep changes</em>. Otherwise
        the appliance rolls back automatically. From the local console: <code>efwctl status</code>,
        <code>efwctl confirm N</code> or <code>efwctl rollback</code>.
      </div>
    {/if}

    <form class="form inline" onsubmit={(e) => (e.preventDefault(), apply())}>
      <label>
        Confirmation window
        <select bind:value={timeout}>
          <option value={60}>1 minute</option>
          <option value={120}>2 minutes</option>
          <option value={300}>5 minutes</option>
          <option value={600}>10 minutes</option>
        </select>
      </label>
      <label class="grow">Note for the history <input bind:value={note} maxlength="500" placeholder="optional" /></label>
      <button class="primary" type="submit" disabled={busy}>Apply for testing</button>
    </form>
  </section>
{/if}
