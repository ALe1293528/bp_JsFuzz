package com.security.jsapihunter.model;

import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicReference;

/**
 * One discovered API endpoint plus the results of every test stage.
 * Mutated by the security modules; read by the UI table model.
 */
public class ApiEndpoint {

    private volatile int seq = 0;       // 1-based sequence number for sorting / display

    private volatile String method = "GET";
    private final String url;          // normalized absolute URL
    private final String rawLink;      // original link as found in JS
    private final String sourceJs;     // JS file the link was found in
    private final long discoveredAt;

    private volatile int statusCode = -1;
    private volatile String alive = "Unknown";      // Alive / Dead / Unknown
    private volatile String unauthorized = "";      // Possible Unauthorized Access / ""
    private volatile String idor = "";              // Possible IDOR / ""
    private volatile String fuzz = "";              // short fuzz finding summary
    private volatile long length = -1;
    private volatile String title = "";

    /** One row per fuzz attempt, each carrying its captured request/response. */
    private final List<FuzzAttempt> fuzzAttempts = new CopyOnWriteArrayList<>();

    private final AtomicReference<RiskLevel> risk = new AtomicReference<>(RiskLevel.LOW);

    public ApiEndpoint(String method, String url, String rawLink, String sourceJs, long discoveredAt) {
        if (method != null && !method.isEmpty()) {
            this.method = method;
        }
        this.url = url;
        this.rawLink = rawLink;
        this.sourceJs = sourceJs;
        this.discoveredAt = discoveredAt;
    }

    /** Dedup key per spec: METHOD + URL. */
    public String key() {
        return method.toUpperCase() + " " + url;
    }

    public int getSeq() { return seq; }
    public void setSeq(int seq) { this.seq = seq; }

    public String getMethod() { return method; }
    public void setMethod(String method) { this.method = method; }

    public String getUrl() { return url; }
    public String getRawLink() { return rawLink; }
    public String getSourceJs() { return sourceJs; }
    public long getDiscoveredAt() { return discoveredAt; }

    public int getStatusCode() { return statusCode; }
    public void setStatusCode(int statusCode) { this.statusCode = statusCode; }

    public String getAlive() { return alive; }
    public void setAlive(String alive) { this.alive = alive; }

    public String getUnauthorized() { return unauthorized; }
    public void setUnauthorized(String unauthorized) { this.unauthorized = unauthorized; }

    public String getIdor() { return idor; }
    public void setIdor(String idor) { this.idor = idor; }

    public String getFuzz() { return fuzz; }
    public void setFuzz(String fuzz) { this.fuzz = fuzz; }

    public List<FuzzAttempt> getFuzzAttempts() { return fuzzAttempts; }
    public void addFuzzAttempt(FuzzAttempt attempt) { if (attempt != null) fuzzAttempts.add(attempt); }

    public long getLength() { return length; }
    public void setLength(long length) { this.length = length; }

    public String getTitle() { return title; }
    public void setTitle(String title) { this.title = title; }

    public RiskLevel getRisk() { return risk.get(); }
    public void setRisk(RiskLevel level) { risk.set(level); }
    public void raiseRisk(RiskLevel level) { risk.updateAndGet(cur -> RiskLevel.max(cur, level)); }
}
