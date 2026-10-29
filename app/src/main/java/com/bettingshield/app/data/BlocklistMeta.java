package com.bettingshield.app.data;

import androidx.annotation.NonNull;
import androidx.room.ColumnInfo;
import androidx.room.Entity;
import androidx.room.PrimaryKey;

/**
 * Tracks blocklist versioning, signature verification status, and update timestamps.
 * Prevents rollback attacks by guaranteeing strictly increasing versions.
 */
@Entity(tableName = "blocklist_meta")
public class BlocklistMeta {

    @PrimaryKey
    @NonNull
    @ColumnInfo(name = "meta_key")
    private String metaKey; // e.g. "active_rules"

    @ColumnInfo(name = "version")
    private int version;

    @ColumnInfo(name = "last_updated")
    private long lastUpdated;

    @ColumnInfo(name = "signature")
    private String signature;

    public BlocklistMeta(@NonNull String metaKey, int version, long lastUpdated, String signature) {
        this.metaKey = metaKey;
        this.version = version;
        this.lastUpdated = lastUpdated;
        this.signature = signature;
    }

    @NonNull
    public String getMetaKey() {
        return metaKey;
    }

    public void setMetaKey(@NonNull String metaKey) {
        this.metaKey = metaKey;
    }

    public int getVersion() {
        return version;
    }

    public void setVersion(int version) {
        this.version = version;
    }

    public long getLastUpdated() {
        return lastUpdated;
    }

    public void setLastUpdated(long lastUpdated) {
        this.lastUpdated = lastUpdated;
    }

    public String getSignature() {
        return signature;
    }

    public void setSignature(String signature) {
        this.signature = signature;
    }
}
