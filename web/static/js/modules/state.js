/**
 * SNMK Enterprise Web UI — Centralized Reactive State Store
 * Implements a lightweight pub/sub state container to decouple UI components
 * from monolithic global window variables.
 */

class ReactiveStore {
  constructor(initialState = {}) {
    this.state = { ...initialState };
    this.listeners = new Map();
  }

  getState() {
    return { ...this.state };
  }

  get(key, defaultValue = undefined) {
    return this.state[key] !== undefined ? this.state[key] : defaultValue;
  }

  set(key, value) {
    const prev = this.state[key];
    if (prev === value) return;
    this.state[key] = value;
    this.notify(key, value, prev);
  }

  update(patch) {
    Object.keys(patch).forEach((key) => {
      this.set(key, patch[key]);
    });
  }

  subscribe(key, callback) {
    if (!this.listeners.has(key)) {
      this.listeners.set(key, new Set());
    }
    this.listeners.get(key).add(callback);
    return () => this.listeners.get(key)?.delete(callback);
  }

  notify(key, value, prev) {
    if (this.listeners.has(key)) {
      this.listeners.get(key).forEach((cb) => {
        try {
          cb(value, prev);
        } catch (e) {
          console.error(`Store listener error on key [${key}]:`, e);
        }
      });
    }
    if (this.listeners.has("*")) {
      this.listeners.get("*").forEach((cb) => {
        try {
          cb(key, value, prev);
        } catch (e) {
          console.error("Store wildcard listener error:", e);
        }
      });
    }
  }
}

export const store = new ReactiveStore({
  currentView: "dashboard",
  activeScanId: null,
  scans: [],
  findings: [],
  subdomains: [],
  agentsSummary: null,
  toolInventory: null,
  authStatus: "AUTHENTICATED",
});
