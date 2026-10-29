package com.bettingshield.app.data;

import androidx.room.ColumnInfo;
import androidx.room.Entity;
import androidx.room.Index;
import androidx.room.PrimaryKey;

/**
 * Represents a domain entry in the local blocklist database.
 * Supports exact domains, wildcard matching, and allowlist exceptions.
 */
@Entity(tableName = "blocked_domains", indices = {@Index(value = {"domain"}, unique = true)})
public class BlockedDomain {

    @PrimaryKey(autoGenerate = true)
    private int id;

    @ColumnInfo(name = "domain")
    private String domain;

    @ColumnInfo(name = "category")
    private String category; // e.g. "sportsbook", "casino", "fantasy", "custom"

    @ColumnInfo(name = "is_allowed")
    private boolean isAllowed; // true for false-positive user whitelist exception

    @ColumnInfo(name = "created_at")
    private long createdAt;

    public BlockedDomain(String domain, String category, boolean isAllowed, long createdAt) {
        this.domain = domain;
        this.category = category;
        this.isAllowed = isAllowed;
        this.createdAt = createdAt;
    }

    public int getId() {
        return id;
    }

    public void setId(int id) {
        this.id = id;
    }

    public String getDomain() {
        return domain;
    }

    public void setDomain(String domain) {
        this.domain = domain;
    }

    public String getCategory() {
        return category;
    }

    public void setCategory(String category) {
        this.category = category;
    }

    public boolean isAllowed() {
        return isAllowed;
    }

    public void setAllowed(boolean allowed) {
        isAllowed = allowed;
    }

    public long getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(long createdAt) {
        this.createdAt = createdAt;
    }
}
