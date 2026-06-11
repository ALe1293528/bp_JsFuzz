package com.security.jsfuzz.security;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Thin wrapper over Montoya's HTTP client for building and sending requests
 * to discovered endpoints. Centralizes request construction so every security
 * module behaves consistently.
 */
public class HttpHelper {

    private final MontoyaApi api;
    private static final Pattern TITLE =
            Pattern.compile("<title[^>]*>(.*?)</title>", Pattern.CASE_INSENSITIVE | Pattern.DOTALL);

    public HttpHelper(MontoyaApi api) {
        this.api = api;
    }

    public HttpRequest build(String method, String url) {
        return HttpRequest.httpRequestFromUrl(url).withMethod(method);
    }

    public HttpRequestResponse send(HttpRequest request) {
        return api.http().sendRequest(request);
    }

    public HttpRequestResponse send(String method, String url) {
        return send(build(method, url));
    }

    public static int statusOf(HttpRequestResponse rr) {
        if (rr == null || rr.response() == null) return -1;
        return rr.response().statusCode();
    }

    public static long bodyLength(HttpRequestResponse rr) {
        if (rr == null || rr.response() == null) return -1;
        return rr.response().body().length();
    }

    public static String titleOf(HttpRequestResponse rr) {
        if (rr == null || rr.response() == null) return "";
        HttpResponse resp = rr.response();
        String body = resp.bodyToString();
        Matcher m = TITLE.matcher(body);
        if (m.find()) {
            return m.group(1).trim().replaceAll("\\s+", " ");
        }
        return "";
    }
}
