package com.security.jsapihunter.security;

import com.security.jsapihunter.model.ApiEndpoint;
import com.security.jsapihunter.model.RiskLevel;

/**
 * Part 7: risk scoring. Computes a final level from all collected signals.
 *
 *   Critical : unauthorized access, IDOR, or sensitive-info leak
 *   High     : clear fuzz bypass / status change / sensitive keyword
 *   Medium   : endpoint reachable but no finding
 *   Low      : endpoint does not exist (Dead / unreachable)
 */
public class RiskEngine {

    public RiskLevel score(ApiEndpoint ep) {
        boolean unauthorized = notEmpty(ep.getUnauthorized());
        boolean idor = notEmpty(ep.getIdor());
        boolean sensitive = ep.getFuzz() != null && ep.getFuzz().contains("sensitive:");
        boolean fuzzFinding = notEmpty(ep.getFuzz());

        RiskLevel level;
        if (unauthorized || idor || sensitive) {
            level = RiskLevel.CRITICAL;
        } else if (fuzzFinding) {
            level = RiskLevel.HIGH;
        } else if ("Alive".equals(ep.getAlive())) {
            level = RiskLevel.MEDIUM;
        } else {
            level = RiskLevel.LOW;
        }

        // Never downgrade below what individual modules already escalated to.
        level = RiskLevel.max(level, ep.getRisk());
        ep.setRisk(level);
        return level;
    }

    private boolean notEmpty(String s) {
        return s != null && !s.isEmpty();
    }
}
