package com.security.jsfuzz.util;

import java.net.URI;

/**
 * Part 3: URL standardization.
 * Restores a link found inside a JS file to a full absolute URL, given the
 * URL of the JS file as the base. Handles:
 *   - absolute URLs            https://x.com/api/user            -> unchanged
 *   - protocol-relative        //cdn.x.com/api/user             -> https://cdn.x.com/api/user
 *   - root-relative            /api/user                        -> https://target.com/api/user
 *   - relative                 api/user , ./api , ../api        -> resolved against base path
 */
public final class UrlNormalizer {

    private UrlNormalizer() {
    }

    public static boolean isAbsolute(String link) {
        if (link == null) return false;
        String l = link.trim().toLowerCase();
        return l.startsWith("http://") || l.startsWith("https://")
                || l.startsWith("ws://") || l.startsWith("wss://");
    }

    /**
     * @param baseJsUrl the absolute URL of the JS file the link was found in
     * @param link      the raw link extracted from the JS
     * @return absolute URL, or the raw link if it cannot be resolved
     */
    public static String normalize(String baseJsUrl, String link) {
        if (link == null || link.isEmpty()) {
            return link;
        }
        String trimmed = link.trim();

        try {
            URI base = URI.create(baseJsUrl);
            String scheme = base.getScheme() == null ? "https" : base.getScheme();

            // Already absolute (http/https/ws/wss).
            if (isAbsolute(trimmed)) {
                return trimmed;
            }

            // Protocol-relative: //cdn.example.com/path
            if (trimmed.startsWith("//")) {
                String s = scheme.startsWith("ws") ? "https" : scheme;
                return s + ":" + trimmed;
            }

            // Resolve everything else (/, ./, ../, plain relative) against the JS URL.
            URI resolved = base.resolve(trimmed);
            // base.resolve on a scheme-less relative may drop the host for odd inputs;
            // guard by rebuilding from authority when needed.
            if (resolved.getHost() == null && base.getHost() != null) {
                String path = trimmed.startsWith("/") ? trimmed : "/" + trimmed;
                return scheme + "://" + base.getAuthority() + path;
            }
            return resolved.toString();
        } catch (Exception e) {
            // Fall back: best-effort root-relative join.
            try {
                URI base = URI.create(baseJsUrl);
                String scheme = base.getScheme() == null ? "https" : base.getScheme();
                String path = trimmed.startsWith("/") ? trimmed : "/" + trimmed;
                return scheme + "://" + base.getAuthority() + path;
            } catch (Exception ignored) {
                return trimmed;
            }
        }
    }

    /** Root URL (scheme://authority) of an absolute URL, or null. */
    public static String rootOf(String absoluteUrl) {
        try {
            URI u = URI.create(absoluteUrl);
            if (u.getScheme() == null || u.getAuthority() == null) {
                return null;
            }
            return u.getScheme() + "://" + u.getAuthority();
        } catch (Exception e) {
            return null;
        }
    }
}
