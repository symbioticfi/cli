export type CacheEntry<T> = {
  value: T
  expiresAtMs: number
}

export class TtlCache<K, V> {
  private readonly store = new Map<K, CacheEntry<V>>()

  constructor(private readonly defaultTtlMs: number) {}

  get(key: K): V | undefined {
    const entry = this.store.get(key)
    if (!entry) return undefined
    if (Date.now() >= entry.expiresAtMs) {
      this.store.delete(key)
      return undefined
    }
    return entry.value
  }

  set(key: K, value: V, ttlMs?: number) {
    this.store.set(key, {
      value,
      expiresAtMs: Date.now() + (ttlMs ?? this.defaultTtlMs),
    })
  }

  clear() {
    this.store.clear()
  }
}

