<script lang="ts">
  import { health } from './format';
  let { adminUp, oper }: { adminUp: boolean; oper: string } = $props();
  const h = $derived(health(adminUp, oper));
  const label = $derived(h === 'disabled' ? 'admin down' : h === 'down' ? `no link (${oper})` : oper);
</script>

<span class="state {h}"><span class="dot" aria-hidden="true"></span>{label}</span>

<style>
  .state {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    white-space: nowrap;
  }
  .dot {
    width: 7px;
    height: 7px;
    border-radius: 50%;
    background: var(--fg-faint);
  }
  .up .dot {
    background: var(--ok);
  }
  .down {
    color: var(--warn-fg);
    font-weight: 600;
  }
  .down .dot {
    background: var(--warn);
  }
  .disabled {
    color: var(--fg-muted);
  }
  .disabled .dot {
    background: transparent;
    border: 1px solid var(--fg-faint);
  }
</style>
