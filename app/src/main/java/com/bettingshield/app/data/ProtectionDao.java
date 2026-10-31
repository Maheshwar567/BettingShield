package com.bettingshield.app.data;

import androidx.lifecycle.LiveData;
import androidx.room.Dao;
import androidx.room.Delete;
import androidx.room.Insert;
import androidx.room.OnConflictStrategy;
import androidx.room.Query;

import java.util.List;

/**
 * Data Access Object for local filtering rules, packages, and metadata.
 */
@Dao
public interface ProtectionDao {

    // Domain queries
    @Query("SELECT * FROM blocked_domains WHERE is_allowed = 0")
    List<BlockedDomain> getAllBlockedDomains();

    @Query("SELECT * FROM blocked_domains WHERE is_allowed = 0")
    LiveData<List<BlockedDomain>> getAllBlockedDomainsLiveData();

    @Query("SELECT * FROM blocked_domains WHERE is_allowed = 1")
    List<BlockedDomain> getAllAllowedExceptions();

    @Query("SELECT * FROM blocked_domains WHERE is_allowed = 1")
    LiveData<List<BlockedDomain>> getAllAllowedExceptionsLiveData();

    @Query("SELECT * FROM blocked_domains WHERE domain = :domain LIMIT 1")
    BlockedDomain findDomain(String domain);

    @Query("SELECT COUNT(*) FROM blocked_domains WHERE is_allowed = 0")
    int getBlockedDomainCount();

    @Query("SELECT COUNT(*) FROM blocked_domains WHERE is_allowed = 0")
    LiveData<Integer> getBlockedDomainCountLiveData();

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    void insertDomain(BlockedDomain domain);

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    void insertDomains(List<BlockedDomain> domains);

    @Delete
    void deleteDomain(BlockedDomain domain);

    @Query("DELETE FROM blocked_domains WHERE domain = :domain")
    void deleteByDomain(String domain);

    @Query("DELETE FROM blocked_domains WHERE is_allowed = 0")
    void clearSyncedBlockedDomains();

    // Package queries
    @Query("SELECT * FROM blocked_packages")
    List<BlockedPackage> getAllBlockedPackages();

    @Query("SELECT * FROM blocked_packages")
    LiveData<List<BlockedPackage>> getAllBlockedPackagesLiveData();

    @Query("SELECT COUNT(*) FROM blocked_packages")
    int getBlockedPackageCount();

    @Query("SELECT COUNT(*) FROM blocked_packages")
    LiveData<Integer> getBlockedPackageCountLiveData();

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    void insertPackage(BlockedPackage pkg);

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    void insertPackages(List<BlockedPackage> packages);

    @Query("DELETE FROM blocked_packages WHERE package_name = :pkg")
    void deletePackage(String pkg);

    @Query("DELETE FROM blocked_packages")
    void clearPackages();

    // Metadata queries
    @Query("SELECT * FROM blocklist_meta WHERE meta_key = :key LIMIT 1")
    BlocklistMeta getMeta(String key);

    @Query("SELECT * FROM blocklist_meta WHERE meta_key = :key LIMIT 1")
    LiveData<BlocklistMeta> getMetaLiveData(String key);

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    void insertMeta(BlocklistMeta meta);
}
