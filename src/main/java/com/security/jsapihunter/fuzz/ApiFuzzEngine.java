package com.security.jsapihunter.fuzz;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.security.jsapihunter.model.ApiEndpoint;
import com.security.jsapihunter.model.FuzzAttempt;
import com.security.jsapihunter.model.RiskLevel;
import com.security.jsapihunter.security.HttpHelper;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

/**
 * Part 6: API fuzzing.
 * Thread pool, max concurrency 20. Implements the nine fuzz strategies from
 * the spec and records anything that looks like a bypass / status change.
 */
public class ApiFuzzEngine {

    public static final int MAX_CONCURRENCY = 20;

    private final HttpHelper http;
    private final ExecutorService pool;

    private static final String[] METHODS =
            {"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"};
    private static final String[] NUM_BOUNDARY =
            {"0", "-1", "1", "999999999", "2147483647"};
    private static final String[] STR_BOUNDARY =
            {"'", "\"", "<>", "../", "../../", "../../../", "AAAAAAAAAAAAAAAAAAAA"};
    private static final String[] EMPTY_PARAMS = {"id=", "name=", "user="};
    private static final String[] IP_HEADERS =
            {"X-Forwarded-For", "X-Real-IP", "X-Originating-IP", "X-Client-IP"};
    private static final String[] CONTENT_TYPES = {
            "application/json", "application/x-www-form-urlencoded",
            "multipart/form-data", "text/plain"
    };

    public ApiFuzzEngine(MontoyaApi api, HttpHelper http) {
        this.http = http;
        this.pool = Executors.newFixedThreadPool(MAX_CONCURRENCY, r -> {
            Thread t = new Thread(r, "api-fuzz");
            t.setDaemon(true);
            return t;
        });
    }

    /** A single fuzz attempt result. */
    public static class FuzzResult {
        public final String label;
        public final int status;
        public final long length;
        public final boolean interesting;
        public final HttpRequestResponse exchange;

        FuzzResult(String label, int status, long length, boolean interesting,
                   HttpRequestResponse exchange) {
            this.label = label;
            this.status = status;
            this.length = length;
            this.interesting = interesting;
            this.exchange = exchange;
        }
    }

    /**
     * Fuzz one endpoint with all nine strategies, in parallel, against a
     * baseline status. Aggregates interesting findings onto the endpoint.
     */
    public List<FuzzResult> fuzz(ApiEndpoint ep, int baselineStatus, long baselineLength) {
        List<Callable<FuzzResult>> tasks = new ArrayList<>();

        // Fuzz 1: HTTP method fuzz.
        for (String method : METHODS) {
            if (method.equalsIgnoreCase(ep.getMethod())) continue;
            tasks.add(() -> attempt("method:" + method,
                    http.build(method, ep.getUrl()), baselineStatus, baselineLength));
        }

        // Fuzz 2 + 3 + 4: numeric / string / empty param boundaries appended to query.
        for (String v : NUM_BOUNDARY) {
            tasks.add(() -> attempt("num:" + v, withParam(ep, "id", v), baselineStatus, baselineLength));
        }
        for (String v : STR_BOUNDARY) {
            tasks.add(() -> attempt("str:" + v, withParam(ep, "q", v), baselineStatus, baselineLength));
        }
        for (String kv : EMPTY_PARAMS) {
            String[] parts = kv.split("=", 2);
            tasks.add(() -> attempt("empty:" + parts[0],
                    withParam(ep, parts[0], ""), baselineStatus, baselineLength));
        }

        // Fuzz 5 + 6: JSON null / boolean bodies (sent as POST).
        tasks.add(() -> attempt("json-null",
                jsonBody(ep, "{\"id\":null}"), baselineStatus, baselineLength));
        tasks.add(() -> attempt("json-admin-true",
                jsonBody(ep, "{\"admin\":true}"), baselineStatus, baselineLength));
        tasks.add(() -> attempt("json-isAdmin-true",
                jsonBody(ep, "{\"isAdmin\":true}"), baselineStatus, baselineLength));

        // Fuzz 7: parameter pollution.
        tasks.add(() -> attempt("pollution:id",
                withRawQuery(ep, "id=1&id=2"), baselineStatus, baselineLength));
        tasks.add(() -> attempt("pollution:uid",
                withRawQuery(ep, "uid=1&uid=2"), baselineStatus, baselineLength));

        // Fuzz 8: spoofed IP headers.
        for (String h : IP_HEADERS) {
            tasks.add(() -> attempt("header:" + h,
                    http.build(ep.getMethod(), ep.getUrl()).withAddedHeader(h, "127.0.0.1"),
                    baselineStatus, baselineLength));
        }

        // Fuzz 9: Content-Type switching.
        for (String ct : CONTENT_TYPES) {
            tasks.add(() -> attempt("ctype:" + ct,
                    http.build("POST", ep.getUrl()).withHeader("Content-Type", ct),
                    baselineStatus, baselineLength));
        }

        List<FuzzResult> results = new ArrayList<>();
        try {
            List<Future<FuzzResult>> futures = pool.invokeAll(tasks);
            for (Future<FuzzResult> f : futures) {
                try {
                    FuzzResult r = f.get();
                    if (r != null) results.add(r);
                } catch (ExecutionException ignored) {
                }
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }

        summarize(ep, baselineStatus, results);
        return results;
    }

    private FuzzResult attempt(String label, HttpRequest req, int baselineStatus, long baselineLength) {
        HttpRequestResponse rr = http.send(req);
        int status = HttpHelper.statusOf(rr);
        long len = HttpHelper.bodyLength(rr);
        // "Interesting" = method/probe now succeeds where it differs from baseline,
        // or a clear access-control bypass (was 401/403, now 2xx).
        boolean bypass = (baselineStatus == 401 || baselineStatus == 403) && status >= 200 && status < 300;
        boolean changed = status > 0 && status != baselineStatus
                && status < 500 && status != 404;
        return new FuzzResult(label, status, len, bypass || changed, rr);
    }

    private void summarize(ApiEndpoint ep, int baselineStatus, List<FuzzResult> results) {
        StringBuilder sb = new StringBuilder();
        boolean bypass = false;
        for (FuzzResult r : results) {
            // One row per attempt; keep its captured request/response for the viewer.
            ep.addFuzzAttempt(new FuzzAttempt(r.label, r.status, r.length, r.interesting, r.exchange));
            if (r.interesting) {
                if (sb.length() > 0) sb.append("; ");
                sb.append(r.label).append("->").append(r.status);
                if ((baselineStatus == 401 || baselineStatus == 403)
                        && r.status >= 200 && r.status < 300) {
                    bypass = true;
                }
            }
        }
        if (sb.length() > 0) {
            String existing = ep.getFuzz();
            ep.setFuzz(existing.isEmpty() ? sb.toString() : existing + "; " + sb);
            ep.raiseRisk(bypass ? RiskLevel.HIGH : RiskLevel.MEDIUM);
        }
    }

    private HttpRequest withParam(ApiEndpoint ep, String name, String value) {
        return http.build(ep.getMethod(), appendQuery(ep.getUrl(), name + "=" + value));
    }

    private HttpRequest withRawQuery(ApiEndpoint ep, String rawQuery) {
        return http.build(ep.getMethod(), appendQuery(ep.getUrl(), rawQuery));
    }

    private HttpRequest jsonBody(ApiEndpoint ep, String json) {
        return http.build("POST", ep.getUrl())
                .withHeader("Content-Type", "application/json")
                .withBody(json);
    }

    private String appendQuery(String url, String kv) {
        return url + (url.contains("?") ? "&" : "?") + kv;
    }

    public void shutdown() {
        pool.shutdownNow();
    }
}
