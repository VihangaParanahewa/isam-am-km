package org.wso2.km.ext.isam.caching;

import javax.cache.Cache;
import javax.cache.CacheConfiguration;
import javax.cache.Caching;
import java.util.concurrent.TimeUnit;

public class CacheManger {
    /**
     * Create the Cache object from the given parameters
     *
     * @param cacheManagerName - Name of the Cache Manager
     * @param cacheName        - Name of the Cache
     * @param modifiedExp      - Value of the MODIFIED Expiry Type
     * @param accessExp        - Value of the ACCESSED Expiry Type
     * @return - The cache object
     */
    public static Cache getCache(final String cacheManagerName, final String cacheName, final long modifiedExp,
                                 final long accessExp) {

        return Caching.getCacheManager(
                        cacheManagerName).createCacheBuilder(cacheName).
                setExpiry(CacheConfiguration.ExpiryType.MODIFIED, new CacheConfiguration.Duration(TimeUnit.SECONDS,
                        modifiedExp)).
                setExpiry(CacheConfiguration.ExpiryType.ACCESSED, new CacheConfiguration.Duration(TimeUnit.SECONDS,
                        accessExp)).setStoreByValue(false).build();
    }
}
