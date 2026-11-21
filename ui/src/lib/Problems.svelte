<script lang="ts">
  import type { Problem } from './api';
  let { problems, message }: { problems: Problem[]; message?: string | null } = $props();
</script>

{#if message || problems.length}
  <div class="banner" role="alert">
    {#if message}<strong>{message}</strong>{/if}
    {#if problems.length}
      <ul class="problems">
        {#each problems as p (p.path + p.message)}
          <li><code>{p.path}</code> — {p.message}</li>
        {/each}
      </ul>
    {/if}
  </div>
{/if}
