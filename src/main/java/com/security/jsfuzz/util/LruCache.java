package com.security.jsfuzz.util;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

/**
 * Bounded, thread-safe LRU set used to avoid re-scanning the same METHOD+URL.
 * Part 9: performance optimization.
 */
public class LruCache<K> {

    private final Map<K, Boolean> map;

    public LruCache(final int maxEntries) {
        LinkedHashMap<K, Boolean> backing = new LinkedHashMap<>(16, 0.75f, true) {
            @Override
            protected boolean removeEldestEntry(Map.Entry<K, Boolean> eldest) {
                return size() > maxEntries;
            }
        };
        this.map = Collections.synchronizedMap(backing);
    }

    /** Returns true if the key was newly added (i.e. not seen before). */
    public boolean add(K key) {
        synchronized (map) {
            if (map.containsKey(key)) {
                return false;
            }
            map.put(key, Boolean.TRUE);
            return true;
        }
    }

    public boolean contains(K key) {
        return map.containsKey(key);
    }

    public Set<K> keys() {
        synchronized (map) {
            return Set.copyOf(map.keySet());
        }
    }

    public int size() {
        return map.size();
    }
}
