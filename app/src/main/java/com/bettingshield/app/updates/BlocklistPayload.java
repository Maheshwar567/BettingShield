package com.bettingshield.app.updates;

import com.google.gson.annotations.SerializedName;
import java.util.List;

/**
 * Data Transfer Object for downloaded blocklist rule updates.
 */
public class BlocklistPayload {

    @SerializedName("version")
    private int version;

    @SerializedName("timestamp")
    private long timestamp;

    @SerializedName("domains")
    private List<String> domains;

    @SerializedName("packages")
    private List<PackageEntry> packages;

    @SerializedName("signature")
    private String signature; // Hex or Base64 encoded digital signature

    public static class PackageEntry {
        @SerializedName("package_name")
        private String packageName;

        @SerializedName("app_name")
        private String appName;

        @SerializedName("category")
        private String category;

        public String getPackageName() { return packageName; }
        public String getAppName() { return appName; }
        public String getCategory() { return category; }
    }

    public int getVersion() { return version; }
    public long getTimestamp() { return timestamp; }
    public List<String> getDomains() { return domains; }
    public List<PackageEntry> getPackages() { return packages; }
    public String getSignature() { return signature; }
}
