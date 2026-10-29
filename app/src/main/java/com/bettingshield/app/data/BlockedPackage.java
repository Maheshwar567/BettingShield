package com.bettingshield.app.data;

import androidx.annotation.NonNull;
import androidx.room.ColumnInfo;
import androidx.room.Entity;
import androidx.room.PrimaryKey;

/**
 * Represents a verified betting application package ID for device detection
 * and network restriction.
 */
@Entity(tableName = "blocked_packages")
public class BlockedPackage {

    @PrimaryKey
    @NonNull
    @ColumnInfo(name = "package_name")
    private String packageName;

    @ColumnInfo(name = "app_name")
    private String appName;

    @ColumnInfo(name = "category")
    private String category; // e.g. "sports_betting", "casino", "fantasy_wagering"

    @ColumnInfo(name = "added_at")
    private long addedAt;

    public BlockedPackage(@NonNull String packageName, String appName, String category, long addedAt) {
        this.packageName = packageName;
        this.appName = appName;
        this.category = category;
        this.addedAt = addedAt;
    }

    @NonNull
    public String getPackageName() {
        return packageName;
    }

    public void setPackageName(@NonNull String packageName) {
        this.packageName = packageName;
    }

    public String getAppName() {
        return appName;
    }

    public void setAppName(String appName) {
        this.appName = appName;
    }

    public String getCategory() {
        return category;
    }

    public void setCategory(String category) {
        this.category = category;
    }

    public long getAddedAt() {
        return addedAt;
    }

    public void setAddedAt(long addedAt) {
        this.addedAt = addedAt;
    }
}
