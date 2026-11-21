// Polls the appliance and keeps the previous sample to derive real rates.
import { api, ApiError, type InterfacesResponse, type SystemResponse } from './api';

export const POLL_MS = 5000;

export interface Sample {
  data: InterfacesResponse;
  at: number; // ms, from observed_at
}

class Live {
  system = $state<SystemResponse | null>(null);
  current = $state<Sample | null>(null);
  previous = $state<Sample | null>(null);
  error = $state<ApiError | null>(null);
  loading = $state(false);
  paused = $state(false);
  #timer: ReturnType<typeof setTimeout> | undefined;
  #ctrl: AbortController | undefined;

  async refresh(): Promise<void> {
    this.#ctrl?.abort();
    const ctrl = (this.#ctrl = new AbortController());
    this.loading = true;
    try {
      const [ifs, sys] = await Promise.all([api.interfaces(ctrl.signal), api.system(ctrl.signal)]);
      const at = Date.parse(ifs.observed_at);
      if (this.current && at > this.current.at) this.previous = this.current;
      this.current = { data: ifs, at };
      this.system = sys;
      this.error = null;
    } catch (e) {
      if (e instanceof DOMException && e.name === 'AbortError') return;
      this.error = e instanceof ApiError ? e : new ApiError(0, 'unknown', String(e));
    } finally {
      if (this.#ctrl === ctrl) this.loading = false;
    }
  }

  start(): () => void {
    const loop = async () => {
      if (!this.paused && document.visibilityState === 'visible') await this.refresh();
      this.#timer = setTimeout(loop, POLL_MS);
    };
    void loop();
    return () => {
      clearTimeout(this.#timer);
      this.#ctrl?.abort();
    };
  }
}

export const live = new Live();
