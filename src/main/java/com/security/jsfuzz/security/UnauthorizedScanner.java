package com.security.jsfuzz.security;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.security.jsfuzz.model.ApiEndpoint;
import com.security.jsfuzz.model.RiskLevel;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Part 5: unauthorized-access / IDOR / sensitive-data detection.
 *
 * Detection 1 - unauthenticated replay: strip auth headers, compare the
 *   no-auth response with the baseline (status, length, content similarity).
 *   < 10% difference => "Possible Unauthorized Access".
 * Detection 2 - identity switch (IDOR): for uid/userId/memberId/accountId
 *   params, try +1 / -1 / random; if still valid data => "Possible IDOR".
 * Detection 3 - sensitive data in response raises the risk level.
 */
public class UnauthorizedScanner {

    private final HttpHelper http;

    private static final String[] AUTH_HEADERS =
            {"Authorization", "Cookie", "Session", "X-Auth-Token", "JWT", "X-Access-Token"};

    private static final String[] SENSITIVE_KEYS = {
            "token", "jwt", "password", "secret", "apikey", "api_key",
            "access_key", "private_key", "admin", "root"
    };

    private static final Pattern ID_PARAM =
            Pattern.compile("([?&](?:uid|userId|memberId|accountId|id)=)(\\d+)", Pattern.CASE_INSENSITIVE);

    public UnauthorizedScanner(HttpHelper http) {
        this.http = http;
    }

    /**
     * @param ep       the endpoint to test (status/length already filled by alive check)
     * @param baseline the baseline request/response from the alive check (with auth, if any)
     */
    public void scan(ApiEndpoint ep, HttpRequestResponse baseline) {
        if (baseline == null || baseline.response() == null) {
            return;
        }
        detectUnauthorized(ep, baseline);
        detectIdor(ep, baseline);
        detectSensitive(ep, baseline);
    }

    // ---- Detection 1 ---------------------------------------------------------

    private void detectUnauthorized(ApiEndpoint ep, HttpRequestResponse baseline) {
        HttpRequest stripped = baseline.request();
        for (String h : AUTH_HEADERS) {
            stripped = stripped.withRemovedHeader(h);
        }
        HttpRequestResponse noAuth = http.send(stripped);
        if (noAuth == null || noAuth.response() == null) {
            return;
        }

        int baseStatus = baseline.response().statusCode();
        int noAuthStatus = noAuth.response().statusCode();
        String baseBody = baseline.response().bodyToString();
        String noAuthBody = noAuth.response().bodyToString();

        // Only meaningful if the baseline itself returned usable data.
        boolean baseUsable = baseStatus >= 200 && baseStatus < 300 && baseBody.length() > 0;
        boolean noAuthUsable = noAuthStatus >= 200 && noAuthStatus < 300;

        if (baseUsable && noAuthUsable) {
            double diff = bodyDifference(baseBody, noAuthBody);
            if (diff < 0.10) {
                ep.setUnauthorized("Possible Unauthorized Access");
                ep.raiseRisk(RiskLevel.CRITICAL);
            }
        }
    }

    /** Relative size+content difference in [0,1]; <0.10 means near-identical. */
    private double bodyDifference(String a, String b) {
        if (a.equals(b)) return 0.0;
        int max = Math.max(a.length(), b.length());
        if (max == 0) return 0.0;
        double lenDiff = Math.abs(a.length() - b.length()) / (double) max;
        // Cheap content check: compare a capped prefix character-by-character.
        int cap = Math.min(Math.min(a.length(), b.length()), 4096);
        int same = 0;
        for (int i = 0; i < cap; i++) {
            if (a.charAt(i) == b.charAt(i)) same++;
        }
        double contentDiff = cap == 0 ? 1.0 : 1.0 - (same / (double) cap);
        return Math.max(lenDiff, contentDiff);
    }

    // ---- Detection 2 ---------------------------------------------------------

    private void detectIdor(ApiEndpoint ep, HttpRequestResponse baseline) {
        Matcher m = ID_PARAM.matcher(ep.getUrl());
        if (!m.find()) {
            return;
        }
        long original;
        try {
            original = Long.parseLong(m.group(2));
        } catch (NumberFormatException e) {
            return;
        }

        long[] candidates = {original + 1, original - 1, (original ^ 0x5bd1e995L) & 0xffff};
        int baseStatus = baseline.response().statusCode();
        long baseLen = baseline.response().body().length();

        for (long cand : candidates) {
            if (cand < 0 || cand == original) continue;
            String mutated = ep.getUrl().substring(0, m.start(2)) + cand + ep.getUrl().substring(m.end(2));
            HttpRequestResponse rr = http.send(ep.getMethod(), mutated);
            if (rr == null || rr.response() == null) continue;
            int status = rr.response().statusCode();
            long len = rr.response().body().length();
            // Still returns valid data and a comparable response => potential IDOR.
            if (status >= 200 && status < 300 && baseStatus >= 200 && baseStatus < 300
                    && len > 0 && Math.abs(len - baseLen) < Math.max(64, baseLen * 0.2)) {
                ep.setIdor("Possible IDOR");
                ep.raiseRisk(RiskLevel.CRITICAL);
                return;
            }
        }
    }

    // ---- Detection 3 ---------------------------------------------------------

    private void detectSensitive(ApiEndpoint ep, HttpRequestResponse baseline) {
        String body = baseline.response().bodyToString().toLowerCase();
        for (String key : SENSITIVE_KEYS) {
            if (body.contains("\"" + key + "\"") || body.contains(key + "=")
                    || body.contains(key + ":")) {
                ep.raiseRisk(RiskLevel.CRITICAL);
                String cur = ep.getFuzz();
                ep.setFuzz((cur.isEmpty() ? "" : cur + "; ") + "sensitive:" + key);
                return;
            }
        }
    }
}
