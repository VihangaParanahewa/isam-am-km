package org.wso2.km.ext.isam.caching;

import org.wso2.km.ext.isam.Constants;

import javax.cache.Cache;

public class CacheProvider {

    public static Cache createIntrospectionCache() {

        return getCache(Constants.IS_AM_KM_CACHE_MANAGER, Constants.INTROSPECT_CACHE_NAME, Constants.CACHE_EXPIRY,
                Constants.CACHE_EXPIRY);
    }

    /**
     * create cache with following parameters
     *
     * @param cacheManagerName Name of the cache manager
     * @param cacheName        Name of the cache need to be created
     * @param modifiedExp      Timeout value
     * @param accessExp        Timeout value
     * @return
     */

    private static Cache getCache(final String cacheManagerName, final String cacheName, final long modifiedExp,
                                  long accessExp) {

        return CacheManger.getCache(cacheManagerName, cacheName, modifiedExp, accessExp);
    }
}