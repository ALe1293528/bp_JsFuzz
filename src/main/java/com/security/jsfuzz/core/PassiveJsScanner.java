package com.security.jsfuzz.core;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Annotations;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.AuditResult;
import burp.api.montoya.scanner.ConsolidationAction;
import burp.api.montoya.scanner.ScanCheck;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import com.security.jsfuzz.model.ApiEndpoint;
import com.security.jsfuzz.security.ApiSecurityManager;
import com.security.jsfuzz.ui.MainUI;
import com.security.jsfuzz.util.UrlNormalizer;

import java.util.ArrayList;
import java.util.List;

import static burp.api.montoya.scanner.AuditResult.auditResult;

/**
 * Passive scan check. Mirrors the original doPassiveScan flow:
 *   - only acts on .js responses, skipping the JS exclusion list
 *   - extracts links (original JSFinder + Part-2 API patterns)
 *   - normalizes each to an absolute URL (Part 3)
 *   - feeds API endpoints into the security pipeline (Parts 4-7)
 *   - raises an informational Burp issue listing the discovered links
 */
public class PassiveJsScanner implements ScanCheck {

    private final MontoyaApi api;
    private final MainUI ui;
    private final JsLinkFinder finder = new JsLinkFinder();
    private final ApiSecurityManager security;

    public PassiveJsScanner(MontoyaApi api, MainUI ui, ApiSecurityManager security) {
        this.api = api;
        this.ui = ui;
        this.security = security;
    }

    @Override
    public AuditResult activeAudit(HttpRequestResponse base, AuditInsertionPoint insertionPoint) {
        return auditResult(List.of());
    }

    @Override
    public AuditResult passiveAudit(HttpRequestResponse rr) {
        try {
            if (rr.request() == null || rr.response() == null) {
                return auditResult(List.of());
            }
            String url = rr.request().url();
            if (url == null || !url.toLowerCase().contains(".js")) {
                return auditResult(List.of());
            }
            if (JsLinkFinder.isExcludedJs(url)) {
                return auditResult(List.of());
            }

            String mime = rr.response().statedMimeType() != null
                    ? rr.response().statedMimeType().name() : "";
            String body = rr.response().bodyToString();
            // Mirror the original: only parse JS/script bodies.
            if (!url.toLowerCase().contains(".js") && !"SCRIPT".equalsIgnoreCase(mime)) {
                return auditResult(List.of());
            }

            // Register this JS site in the left list of the Main tab.
            ui.linkFinder().recordSite(url);

            List<JsLinkFinder.Found> found = finder.extractAll(body);
            List<String> links = new ArrayList<>();
            long now = System.currentTimeMillis();

            for (JsLinkFinder.Found f : found) {
                links.add(f.link);

                String absolute = UrlNormalizer.isAbsolute(f.link)
                        ? f.link
                        : UrlNormalizer.normalize(url, f.link);

                // Paths box + filenames box, grouped under this site.
                ui.linkFinder().addPath(url, absolute);
                addFilename(url, f.link);

                // Only HTTP(S) endpoints go through API security testing.
                if (absolute != null
                        && (absolute.startsWith("http://") || absolute.startsWith("https://"))) {
                    ApiEndpoint ep = new ApiEndpoint(f.method, absolute, f.link, url, now);
                    security.setFuzzEnabled(ui.apiSecurity().isFuzzEnabled());
                    ui.apiSecurity().addEndpoint(ep);
                    security.submit(ep, done -> ui.apiSecurity().refreshEndpoint(done));
                }
            }

            if (links.isEmpty()) {
                return auditResult(List.of());
            }
            return auditResult(List.of(buildIssue(rr, links)));
        } catch (Exception e) {
            api.logging().logToError("[JsFuzz] passive scan error: " + e.getMessage());
            return auditResult(List.of());
        }
    }

    private void addFilename(String siteUrl, String link) {
        String name = link;
        int slash = name.lastIndexOf('/');
        if (slash >= 0) name = name.substring(slash + 1);
        int q = name.indexOf('?');
        if (q >= 0) name = name.substring(0, q);
        if (name.contains(".")) {
            ui.linkFinder().addFile(siteUrl, name);
        }
    }

    private AuditIssue buildIssue(HttpRequestResponse rr, List<String> links) {
        StringBuilder detail = new StringBuilder(
                "JsFuzz analysed this JS file and discovered the following endpoints:<ul>");
        for (String link : links) {
            detail.append("<li>").append(escapeHtml(link)).append("</li>");
        }
        detail.append("</ul>See the <b>API Security</b> tab for liveness, "
                + "unauthorized-access, IDOR, fuzz and risk results.");

        return AuditIssue.auditIssue(
                "JsFuzz - Endpoints discovered in JS file",
                detail.toString(),
                null,
                rr.request().url(),
                AuditIssueSeverity.INFORMATION,
                AuditIssueConfidence.CERTAIN,
                "JS files contain links to other parts of the application.",
                null,
                AuditIssueSeverity.INFORMATION,
                rr);
    }

    private String escapeHtml(String s) {
        if (s == null) return "";
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;");
    }

    @Override
    public ConsolidationAction consolidateIssues(AuditIssue newIssue, AuditIssue existingIssue) {
        return newIssue.name().equals(existingIssue.name())
                && newIssue.baseUrl().equals(existingIssue.baseUrl())
                ? ConsolidationAction.KEEP_EXISTING
                : ConsolidationAction.KEEP_BOTH;
    }
}
