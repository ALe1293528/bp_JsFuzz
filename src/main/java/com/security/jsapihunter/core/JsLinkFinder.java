package com.security.jsapihunter.core;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Core JS endpoint extraction.
 *
 * Part 1 (preserved): the original LinkFinder/JSFinder regex, ported verbatim
 *   from FransLinkfinder.py (linkAnalyse.regex_str).
 * Part 2 (new): API-aware extraction for fetch / axios / XMLHttpRequest /
 *   jQuery / GraphQL / WebSocket, plus REST path-feature matching.
 *
 * Stateless and thread-safe.
 */
public class JsLinkFinder {

    /** Casual JS files to skip, ported from JSExclusionList. */
    public static final String[] JS_EXCLUSION_LIST =
            {"jquery", "google-analytics", "gpt.js", "modernizr", "gtm", "fbevents"};

    /**
     * Original LinkFinder regex (Python VERBOSE -> single-line Java).
     * Group 1 is the captured link.
     */
    private static final Pattern LINKFINDER = Pattern.compile(
            "(?:\"|')(" +
            "((?:[a-zA-Z]{1,10}://|//)[^\"'/]{1,}\\.[a-zA-Z]{2,}[^\"']{0,})" +
            "|" +
            "((?:/|\\.\\./|\\./)[^\"'><,;| *()(%$^/\\\\\\[\\]][^\"'><,;|()]{1,})" +
            "|" +
            "([a-zA-Z0-9_\\-/]{1,}/[a-zA-Z0-9_\\-/.]{1,}\\.(?:[a-zA-Z]{1,4}|action)(?:[?|/][^\"|']{0,}|))" +
            "|" +
            "([a-zA-Z0-9_\\-/]{1,}/[a-zA-Z0-9_\\-/]{3,}(?:[?|#][^\"|']{0,}|))" +
            "|" +
            "([a-zA-Z0-9_\\-]{1,}\\.(?:php|asp|aspx|jsp|json|action|html|js|txt|xml)(?:\\?[^\"|']{0,}|))" +
            ")(?:\"|')");

    // ---- Part 2: API-call aware patterns -------------------------------------

    private static final String URL_LITERAL = "['\"`]([^'\"`]+)['\"`]";

    private static final Pattern FETCH =
            Pattern.compile("fetch\\s*\\(\\s*" + URL_LITERAL);

    private static final Pattern AXIOS =
            Pattern.compile("axios\\s*\\.\\s*(get|post|put|patch|delete|request)\\s*\\(\\s*" + URL_LITERAL,
                    Pattern.CASE_INSENSITIVE);

    // axios({ url: '...' , method: '...' })
    private static final Pattern AXIOS_CONFIG =
            Pattern.compile("axios\\s*\\(\\s*\\{[^}]*url\\s*:\\s*" + URL_LITERAL, Pattern.CASE_INSENSITIVE);

    private static final Pattern XHR_OPEN =
            Pattern.compile("\\.open\\s*\\(\\s*['\"](GET|POST|PUT|PATCH|DELETE|OPTIONS|HEAD)['\"]\\s*,\\s*"
                    + URL_LITERAL, Pattern.CASE_INSENSITIVE);

    private static final Pattern JQUERY =
            Pattern.compile("\\$\\s*\\.\\s*(ajax|get|post|load|getJSON)\\s*\\(\\s*" + URL_LITERAL,
                    Pattern.CASE_INSENSITIVE);

    // $.ajax({ url: '...' })
    private static final Pattern JQUERY_AJAX_CONFIG =
            Pattern.compile("\\$\\s*\\.\\s*ajax\\s*\\(\\s*\\{[^}]*url\\s*:\\s*" + URL_LITERAL,
                    Pattern.CASE_INSENSITIVE);

    private static final Pattern GRAPHQL =
            Pattern.compile("['\"`](/?[a-zA-Z0-9_\\-/]*graphql[a-zA-Z0-9_\\-/]*)['\"`]",
                    Pattern.CASE_INSENSITIVE);

    private static final Pattern WEBSOCKET =
            Pattern.compile("(wss?://[^'\"`\\s]+)", Pattern.CASE_INSENSITIVE);

    /** REST path features per spec Part 2. */
    private static final String[] REST_FEATURES = {
            "/api/", "/v1/", "/v2/", "/v3/", "/auth/", "/admin/", "/user/",
            "/member/", "/account/", "/order/", "/pay/", "/system/"
    };

    private static final Pattern REST_PATH =
            Pattern.compile("['\"`]((?:/[a-zA-Z0-9_\\-]+){1,}/?(?:\\?[^'\"`]*)?)['\"`]");

    /** A discovered link with an inferred HTTP method and a source tag. */
    public static class Found {
        public final String link;
        public final String method;
        public final String via;

        public Found(String link, String method, String via) {
            this.link = link;
            this.method = method;
            this.via = via;
        }
    }

    /**
     * Run the ORIGINAL LinkFinder regex only. Mirrors linkAnalyse.parser_file:
     * returns de-duplicated raw link strings, preserving discovery order.
     */
    public List<String> extractLinks(String content) {
        List<String> out = new ArrayList<>();
        if (content == null) return out;
        Set<String> seen = new LinkedHashSet<>();
        Matcher m = LINKFINDER.matcher(content);
        while (m.find()) {
            String link = m.group(1);
            if (link != null && seen.add(link)) {
                out.add(link);
            }
        }
        return out;
    }

    /**
     * Full extraction: original LinkFinder links PLUS Part-2 API-aware matches,
     * each carrying an inferred HTTP method. De-duplicated by method+link.
     */
    public List<Found> extractAll(String content) {
        List<Found> out = new ArrayList<>();
        if (content == null) return out;
        Set<String> seen = new LinkedHashSet<>();

        // 1) Preserve original JSFinder behaviour (method unknown -> GET).
        for (String link : extractLinks(content)) {
            add(out, seen, link, "GET", "linkfinder");
        }

        // 2) fetch()
        collect(content, FETCH, 1, "GET", "fetch", out, seen);

        // 3) axios.<verb>()
        Matcher am = AXIOS.matcher(content);
        while (am.find()) {
            add(out, seen, am.group(2), am.group(1).toUpperCase(), "axios");
        }
        collect(content, AXIOS_CONFIG, 1, "GET", "axios", out, seen);

        // 4) XMLHttpRequest / xhr.open(method, url)
        Matcher xm = XHR_OPEN.matcher(content);
        while (xm.find()) {
            add(out, seen, xm.group(2), xm.group(1).toUpperCase(), "xhr");
        }

        // 5) jQuery $.ajax/get/post/load/getJSON
        Matcher jm = JQUERY.matcher(content);
        while (jm.find()) {
            String fn = jm.group(1).toLowerCase();
            String method = fn.equals("post") ? "POST" : "GET";
            add(out, seen, jm.group(2), method, "jquery");
        }
        collect(content, JQUERY_AJAX_CONFIG, 1, "GET", "jquery", out, seen);

        // 6) GraphQL endpoints
        collect(content, GRAPHQL, 1, "POST", "graphql", out, seen);

        // 7) WebSocket
        collect(content, WEBSOCKET, 1, "GET", "websocket", out, seen);

        // 8) REST feature paths
        Matcher rm = REST_PATH.matcher(content);
        while (rm.find()) {
            String path = rm.group(1);
            String lower = path.toLowerCase();
            for (String feat : REST_FEATURES) {
                if (lower.contains(feat)) {
                    add(out, seen, path, "GET", "rest");
                    break;
                }
            }
        }

        return out;
    }

    private void collect(String content, Pattern p, int group, String method,
                         String via, List<Found> out, Set<String> seen) {
        Matcher m = p.matcher(content);
        while (m.find()) {
            add(out, seen, m.group(group), method, via);
        }
    }

    private void add(List<Found> out, Set<String> seen, String link, String method, String via) {
        if (link == null) return;
        link = link.trim();
        if (link.isEmpty()) return;
        String key = method + " " + link;
        if (seen.add(key)) {
            out.add(new Found(link, method, via));
        }
    }

    public static boolean isExcludedJs(String url) {
        if (url == null) return false;
        String lower = url.toLowerCase();
        for (String x : JS_EXCLUSION_LIST) {
            if (lower.contains(x)) {
                return true;
            }
        }
        return false;
    }
}
