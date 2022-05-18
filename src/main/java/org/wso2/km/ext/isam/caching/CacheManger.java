/*
 *
 *   Copyright (c) 2020, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *   WSO2 Inc. licenses this file to you under the Apache License,
 *   Version 2.0 (the "License"); you may not use this file except
 *   in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing,
 *   software distributed under the License is distributed on an
 *   "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *   KIND, either express or implied.  See the License for the
 *   specific language governing permissions and limitations
 *   under the License.
 *
 */

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
