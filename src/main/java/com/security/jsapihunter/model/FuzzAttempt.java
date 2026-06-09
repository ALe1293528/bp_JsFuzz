package com.security.jsapihunter.model;

import burp.api.montoya.http.message.HttpRequestResponse;

/**
 * One fuzz attempt: the label, the result, and the captured request/response
 * exchange so the UI can show the real packets (Burp-style) on click.
 */
public class FuzzAttempt {

    private final String label;
    private final int status;
    private final long length;
    private final boolean interesting;
    private final HttpRequestResponse exchange;

    public FuzzAttempt(String label, int status, long length,
                       boolean interesting, HttpRequestResponse exchange) {
        this.label = label;
        this.status = status;
        this.length = length;
        this.interesting = interesting;
        this.exchange = exchange;
    }

    public String getLabel() { return label; }
    public int getStatus() { return status; }
    public long getLength() { return length; }
    public boolean isInteresting() { return interesting; }
    public HttpRequestResponse getExchange() { return exchange; }
}
