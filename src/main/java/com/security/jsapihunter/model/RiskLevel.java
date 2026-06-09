package com.security.jsapihunter.model;

/**
 * Risk classification used by RiskEngine and the API Security table.
 */
public enum RiskLevel {
    LOW(0, "Low"),
    MEDIUM(1, "Medium"),
    HIGH(2, "High"),
    CRITICAL(3, "Critical");

    private final int weight;
    private final String label;

    RiskLevel(int weight, String label) {
        this.weight = weight;
        this.label = label;
    }

    public int weight() {
        return weight;
    }

    public String label() {
        return label;
    }

    public static RiskLevel max(RiskLevel a, RiskLevel b) {
        if (a == null) return b;
        if (b == null) return a;
        return a.weight >= b.weight ? a : b;
    }

    @Override
    public String toString() {
        return label;
    }
}
