package com.security.jsfuzz.security;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import com.security.jsfuzz.fuzz.ApiFuzzEngine;
import com.security.jsfuzz.model.ApiEndpoint;
import com.security.jsfuzz.model.FuzzAttempt;
import com.security.jsfuzz.util.LruCache;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.function.Consumer;

/**
 * Orchestrates the full API-security pipeline for each discovered endpoint:
 *   alive check (Part 4) -> unauthorized/IDOR/sensitive (Part 5)
 *   -> fuzz (Part 6) -> risk scoring (Part 7).
 *
 * Part 9: ExecutorService + ConcurrentHashMap + LRU cache keyed on METHOD+URL
 * so the same endpoint is never tested twice.
 */
public class ApiSecurityManager {

    private final MontoyaApi api;
    private final HttpHelper http;
    private final ApiAliveChecker aliveChecker;
    private final UnauthorizedScanner unauthorizedScanner;
    private final ApiFuzzEngine fuzzEngine;
    private final RiskEngine riskEngine;

    private final ExecutorService dispatcher;
    private final ConcurrentHashMap<String, ApiEndpoint> registry = new ConcurrentHashMap<>();
    private final LruCache<String> scanned = new LruCache<>(5000);

    private volatile boolean fuzzEnabled = true;

    public ApiSecurityManager(MontoyaApi api) {
        this.api = api;
        this.http = new HttpHelper(api);
        this.aliveChecker = new ApiAliveChecker(http);
        this.unauthorizedScanner = new UnauthorizedScanner(http);
        this.fuzzEngine = new ApiFuzzEngine(api, http);
        this.riskEngine = new RiskEngine();
        this.dispatcher = Executors.newFixedThreadPool(8, r -> {
            Thread t = new Thread(r, "api-sec-dispatch");
            t.setDaemon(true);
            return t;
        });
    }

    public void setFuzzEnabled(boolean enabled) {
        this.fuzzEnabled = enabled;
    }

    /**
     * Submit an endpoint for testing. De-duplicated via the LRU cache on
     * METHOD+URL. onResult is invoked (off the EDT) once testing completes.
     */
    public void submit(ApiEndpoint ep, Consumer<ApiEndpoint> onResult) {
        String key = ep.key();
        if (!scanned.add(key)) {
            return; // already scanned
        }
        registry.put(key, ep);
        dispatcher.submit(() -> {
            try {
                runPipeline(ep);
            } catch (Exception e) {
                api.logging().logToError("[JsFuzz] pipeline error for "
                        + ep.getUrl() + ": " + e.getMessage());
            } finally {
                if (onResult != null) {
                    onResult.accept(ep);
                }
            }
        });
    }

    private void runPipeline(ApiEndpoint ep) {
        // Part 4
        HttpRequestResponse baseline = aliveChecker.check(ep);

        // Record the baseline request/response as the first attempt row.
        ep.addFuzzAttempt(new FuzzAttempt("baseline:" + ep.getMethod(),
                ep.getStatusCode(), ep.getLength(), false, baseline));

        // Only pursue deeper tests if the endpoint responded at all.
        if (ep.getStatusCode() > 0) {
            // Part 5
            unauthorizedScanner.scan(ep, baseline);
            // Part 6
            if (fuzzEnabled) {
                fuzzEngine.fuzz(ep, ep.getStatusCode(), ep.getLength());
            }
        }
        // Part 7
        riskEngine.score(ep);
    }

    public void shutdown() {
        dispatcher.shutdownNow();
        fuzzEngine.shutdown();
    }
}
