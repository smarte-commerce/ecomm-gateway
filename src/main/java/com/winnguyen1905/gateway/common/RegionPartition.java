package com.winnguyen1905.gateway.common;

import lombok.Getter;

/**
 * Represents different geographical regions for multi-region deployment.
 * Used for routing requests to appropriate regional services and databases.
 */
@Getter
public enum RegionPartition {
    US("us", "United States", "America/New_York"),
    EU("eu", "Europe", "Europe/London"),
    ASIA("asia", "Asia Pacific", "Asia/Singapore");

    private final String code;
    private final String displayName;
    private final String timeZone;

    RegionPartition(String code, String displayName, String timeZone) {
        this.code = code;
        this.displayName = displayName;
        this.timeZone = timeZone;
    }

    /**
     * Get region from code string (case-insensitive)
     */
    public static RegionPartition fromCode(String code) {
        if (code == null || code.trim().isEmpty()) {
            return US; // Default fallback
        }
        
        for (RegionPartition region : values()) {
            if (region.code.equalsIgnoreCase(code.trim())) {
                return region;
            }
        }
        return US; // Default fallback
    }

    /**
     * Get region based on country code
     */
    public static RegionPartition fromCountry(String countryCode) {
        if (countryCode == null || countryCode.length() != 2) {
            return US; // Default fallback
        }
        
        return switch (countryCode.toUpperCase()) {
            case "US", "CA", "MX" -> US;
            case "GB", "DE", "FR", "IT", "ES", "NL", "BE", "PT", "IE", "AT", "CH", "SE", "NO", "DK", "FI" -> EU;
            case "CN", "JP", "KR", "IN", "SG", "MY", "TH", "VN", "ID", "PH", "AU", "NZ" -> ASIA;
            default -> US;
        };
    }

    /**
     * Get region based on continent
     */
    public static RegionPartition fromContinent(String continent) {
        if (continent == null) {
            return US; // Default fallback
        }
        
        return switch (continent.toLowerCase()) {
            case "europe" -> EU;
            case "asia", "oceania" -> ASIA;
            case "north america", "south america" -> US;
            default -> US;
        };
    }

    // Pre-defined constants for easy access
    public static final RegionPartition US_PARTITION = RegionPartition.US;
    public static final RegionPartition EU_PARTITION = RegionPartition.EU;
    public static final RegionPartition ASIA_PARTITION = RegionPartition.ASIA;
} 