package com.security.jsfuzz;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.extension.ExtensionUnloadingHandler;
import com.security.jsfuzz.core.PassiveJsScanner;
import com.security.jsfuzz.security.ApiSecurityManager;
import com.security.jsfuzz.ui.MainUI;

/**
 * Montoya entry point for JsFuzz Pro.
 * Replaces the Jython BurpExtender.registerExtenderCallbacks.
 */
public class JsFuzzExtension implements BurpExtension {

    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName("JsFuzz");

        MainUI ui = new MainUI(api);
        ApiSecurityManager security = new ApiSecurityManager(api);
        PassiveJsScanner scanner = new PassiveJsScanner(api, ui, security);

        api.scanner().registerScanCheck(scanner);
        api.userInterface().registerSuiteTab("JsFuzz", ui.component());

        api.extension().registerUnloadingHandler((ExtensionUnloadingHandler) security::shutdown);

        api.logging().logToOutput("JsFuzz loaded.");
        api.logging().logToOutput("Evolved from BurpJSLinkFinder (c) 2022 Frans Hendrik Botes.");
    }
}
