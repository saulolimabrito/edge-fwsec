<script lang="ts">
  import { api, ApiError } from './api';
  import { app } from './state.svelte';

  let mode = $state<'login' | 'bootstrap'>(app.session?.needs_bootstrap ? 'bootstrap' : 'login');
  let username = $state('admin');
  let password = $state('');
  let confirm = $state('');
  let token = $state('');
  let error = $state<string | null>(null);
  let busy = $state(false);

  async function submit(e: SubmitEvent) {
    e.preventDefault();
    error = null;
    if (mode === 'bootstrap' && password !== confirm) {
      error = 'The passwords do not match.';
      return;
    }
    busy = true;
    try {
      const s = mode === 'login' ? await api.login(username, password) : await api.bootstrap(token, username, password);
      app.setSession({ ...s, needs_bootstrap: false, bootstrap_pending: false });
      password = confirm = token = '';
    } catch (err) {
      error = err instanceof ApiError ? err.message : String(err);
    } finally {
      busy = false;
    }
  }
</script>

<div class="auth">
  <div class="auth-box">
    <div class="brand"><span class="mark" aria-hidden="true"></span>edge<span class="slash">/</span>fwsec</div>
    <h1>{mode === 'login' ? 'Sign in' : 'Set up administrator'}</h1>
    {#if mode === 'bootstrap'}
      <p class="muted">
        Enter the one-time credential shown on the appliance console. If you do not have one, run
        <code>efwctl bootstrap</code> on the local console. Using it creates the administrator or resets the password
        of an existing one.
      </p>
    {/if}
    <form class="form" onsubmit={submit}>
      {#if mode === 'bootstrap'}
        <label>One-time credential <input name="token" autocomplete="one-time-code" bind:value={token} required placeholder="XXXX-XXXX-XXXX-XXXX-XXXX-XXXX" class="mono" /></label>
      {/if}
      <label>Username <input name="username" autocomplete="username" bind:value={username} required /></label>
      <label>
        Password
        <input name="password" type="password" autocomplete={mode === 'login' ? 'current-password' : 'new-password'} bind:value={password} required minlength={mode === 'bootstrap' ? 12 : undefined} />
      </label>
      {#if mode === 'bootstrap'}
        <label>Repeat password <input type="password" autocomplete="new-password" bind:value={confirm} required /></label>
        <p class="hint">At least 12 characters, not containing the username.</p>
      {/if}
      {#if error}<p class="err" role="alert">{error}</p>{/if}
      <div class="row">
        <button class="primary" type="submit" disabled={busy}>{busy ? 'Working…' : mode === 'login' ? 'Sign in' : 'Create administrator'}</button>
        <button type="button" class="link" onclick={() => ((mode = mode === 'login' ? 'bootstrap' : 'login'), (error = null))}>
          {mode === 'login' ? 'Use a one-time credential' : 'Back to sign in'}
        </button>
      </div>
    </form>
  </div>
</div>
