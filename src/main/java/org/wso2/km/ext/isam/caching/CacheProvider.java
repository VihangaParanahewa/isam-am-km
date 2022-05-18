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
