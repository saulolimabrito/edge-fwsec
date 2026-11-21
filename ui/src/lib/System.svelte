<script lang="ts">
  import { onMount } from 'svelte';
  import { api, ApiError, type Problem, type RestorePreview, type TLSInfo } from './api';
  import { app } from './state.svelte';
  import Problems from './Problems.svelte';

  let tls = $state<TLSInfo | null>(null);
  let certPem = $state('');
  let keyPem = $state('');
  let tlsMsg = $state<string | null>(null);
  let preview = $state<RestorePreview | null>(null);
  let restoreMsg = $state<string | null>(null);
  let restoreProblems = $state<Problem[]>([]);
  let pw = $state({ current: '', next: '', again: '' });
  let pwMsg = $state<string | null>(null);

  onMount(async () => {
    try {
      tls = await api.tls();
    } catch {
      tls = null;
    }
  });

  async function upload(e: SubmitEvent) {
    e.preventDefault();
    tlsMsg = null;
    try {
      tls = await api.tlsUpload(certPem, keyPem);
      certPem = keyPem = '';
      tlsMsg = 'Certificate installed. New connections use it now.';
    } catch (err) {
      tlsMsg = err instanceof ApiError ? err.message : String(err);
    }
  }
  async function revertTls() {
    try {
      tls = await api.tlsRemove();
      tlsMsg = 'Back to the self-signed certificate.';
    } catch (err) {
      tlsMsg = err instanceof ApiError ? err.message : String(err);
    }
  }
  async function pickBackup(e: Event) {
    const f = (e.currentTarget as HTMLInputElement).files?.[0];
    preview = null;
    restoreMsg = null;
    restoreProblems = [];
    if (!f) return;
    try {
      preview = await api.restorePreview(f);
    } catch (err) {
      if (err instanceof ApiError) {
        restoreMsg = err.message;
        restoreProblems = err.problems;
      } else restoreMsg = String(err);
    }
  }
  function useBackup() {
    if (!preview) return;
    app.draft = preview.config;
    location.hash = '#/changes';
  }
  async function changePassword(e: SubmitEvent) {
    e.preventDefault();
    pwMsg = null;
    if (pw.next !== pw.again) return void (pwMsg = 'The new passwords do not match.');
    try {
      const s = await api.password(pw.current, pw.next);
      app.setSession({ ...app.session!, ...s });
      pw = { current: '', next: '', again: '' };
      pwMsg = 'Password changed. Other sessions of this account were signed out.';
    } catch (err) {
      pwMsg = err instanceof ApiError ? err.message : String(err);
    }
  }
</script>

<section aria-labelledby="h-backup">
  <h2 id="h-backup">Backup and restore</h2>
  <p class="note">
    A backup contains the confirmed configuration and its metadata. It never contains accounts, password hashes or the TLS
    private key. Restoring loads the backup into the draft; it is applied like any other change, with a confirmation window.
  </p>
  <div class="row">
    {#if app.confirmedRevision > 0}<a class="button" href="/api/v1/backup" download>Download revision {app.confirmedRevision}</a>{:else}<span class="muted">Nothing to back up yet.</span>{/if}
    <label class="button">Restore from file… <input class="sr-only" type="file" accept="application/json,.json" onchange={pickBackup} /></label>
  </div>
  <Problems problems={restoreProblems} message={restoreMsg} />
  {#if preview}
    <div class="editor">
      <p>
        Backup of revision {preview.info.revision}, exported {new Date(preview.info.exported_at).toLocaleString()} by
        {preview.info.exported_by} (version {preview.info.app_version}{preview.info.migrated_from ? `, migrated from schema ${preview.info.migrated_from}` : ''}).
        {preview.diff === '' ? 'Its ruleset is identical to the confirmed revision.' : 'Its ruleset differs from the confirmed revision.'}
      </p>
      <button class="primary" onclick={useBackup}>Load into draft and review</button>
    </div>
  {/if}
</section>

<section aria-labelledby="h-tls">
  <h2 id="h-tls">Console certificate</h2>
  {#if tls}
    <dl class="facts">
      <div><dt>Type</dt><dd>{tls.custom ? 'installed by an administrator' : 'self-signed by the appliance'}</dd></div>
      <div><dt>Subject</dt><dd>{tls.subject}</dd></div>
      <div><dt>Names</dt><dd class="mono">{[...(tls.dns_names ?? []), ...(tls.ip_addresses ?? [])].join(', ')}</dd></div>
      <div><dt>Valid until</dt><dd>{new Date(tls.not_after).toLocaleDateString()}</dd></div>
      <div class="wide"><dt>SHA-256 fingerprint</dt><dd class="mono small">{tls.sha256}</dd></div>
    </dl>
  {/if}
  <form class="form editor" onsubmit={upload}>
    <label>Certificate chain (PEM) <textarea class="mono" rows="5" bind:value={certPem} required></textarea></label>
    <label>Private key (PEM, ECDSA P-256/P-384 or RSA ≥ 2048) <textarea class="mono" rows="5" bind:value={keyPem} required autocomplete="off"></textarea></label>
    <div class="row">
      <button class="primary" type="submit">Install certificate</button>
      {#if tls?.custom}<button type="button" onclick={revertTls}>Return to self-signed</button>{/if}
    </div>
    {#if tlsMsg}<p class="note" role="status">{tlsMsg}</p>{/if}
  </form>
</section>

<section aria-labelledby="h-pw">
  <h2 id="h-pw">Password for {app.session?.user}</h2>
  <form class="form inline" onsubmit={changePassword}>
    <label>Current <input type="password" autocomplete="current-password" bind:value={pw.current} required /></label>
    <label>New <input type="password" autocomplete="new-password" minlength="12" bind:value={pw.next} required /></label>
    <label>Repeat <input type="password" autocomplete="new-password" bind:value={pw.again} required /></label>
    <button type="submit">Change password</button>
  </form>
  {#if pwMsg}<p class="note" role="status">{pwMsg}</p>{/if}
</section>
