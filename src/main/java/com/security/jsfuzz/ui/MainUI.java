package com.security.jsfuzz.ui;

import burp.api.montoya.MontoyaApi;

import javax.swing.JTabbedPane;
import java.awt.Component;

/**
 * Top-level UI: keeps the original LinkFinder "Main" tab and adds the new
 * "API Security" tab (Part 8).
 */
public class MainUI {

    private final JTabbedPane root = new JTabbedPane();
    private final LinkFinderPanel linkFinderPanel = new LinkFinderPanel();
    private final ApiSecurityPanel apiSecurityPanel;

    public MainUI(MontoyaApi api) {
        this.apiSecurityPanel = new ApiSecurityPanel(api);
        root.addTab("Main", linkFinderPanel);
        root.addTab("API Security", apiSecurityPanel);
    }

    public Component component() {
        return root;
    }

    public LinkFinderPanel linkFinder() {
        return linkFinderPanel;
    }

    public ApiSecurityPanel apiSecurity() {
        return apiSecurityPanel;
    }
}
