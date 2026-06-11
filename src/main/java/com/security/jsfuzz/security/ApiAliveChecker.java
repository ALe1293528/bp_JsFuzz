package com.security.jsfuzz.security;

import burp.api.montoya.http.message.HttpRequestResponse;
import com.security.jsfuzz.model.ApiEndpoint;

/**
 * Part 4: endpoint liveness detection.
 * Tries HEAD first, falls back to GET. Classifies the result:
 *   200-399 -> Alive
 *   404     -> Dead
 *   other   -> Unknown
 */
public class ApiAliveChecker {

    private final HttpHelper http;

    public ApiAliveChecker(HttpHelper http) {
        this.http = http;
    }

    /** Probes the endpoint and fills in status / alive / length / title. */
    public HttpRequestResponse check(ApiEndpoint ep) {
        HttpRequestResponse rr = http.send("HEAD", ep.getUrl());
        int status = HttpHelper.statusOf(rr);

        // Many servers reject HEAD; retry with GET on failure or 405.
        if (status < 0 || status == 405) {
            rr = http.send("GET", ep.getUrl());
            status = HttpHelper.statusOf(rr);
        }

        ep.setStatusCode(status);
        ep.setAlive(classify(status));
        ep.setLength(HttpHelper.bodyLength(rr));
        ep.setTitle(HttpHelper.titleOf(rr));
        return rr;
    }

    public static String classify(int status) {
        if (status >= 200 && status <= 399) return "Alive";
        if (status == 404) return "Dead";
        return "Unknown";
    }
}
