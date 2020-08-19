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

package org.wso2.km.ext.isam;

public final class Constants {

    public static final String ISAM_AUTH_ENDPOINT_URL_CONTEXT = "/sps/oauth/oauth20";

    public static final String CONFIG_ISAM_ENDPOINT_URL = "IsamKm.ServerURL";
    public static final String CONFIG_TOKEN_LENGTH = "IsamKm.TokenLength";
    public static final String CONFIG_CLIENT_ID = "IsamKm.ClientId";
    public static final String CONFIG_CLIENT_SECRET = "IsamKm.ClientSecret";

    public static final String AUTH_HEADER = "Authorization";
    public static final String CLIENT_ID = "client_id";
    public static final String CLIENT_SECRET = "client_secret";
    public static final String GRANT_TYPE = "grant_type";
    public static final String GRANT_CLIENT_CREDENTIALS = "client_credentials";
    public static final String ACCESS_TOKEN = "access_token";
    public static final String BEARER = "Bearer";
    public static final String TOKEN = "token";
    public static final String ACTIVE = "active";
    public static final String EXPIRY = "exp";
    public static final String SCOPE = "scope";

    public static final String RESOURCE_CLIENT_REGISTRATION = "/register";
    public static final String RESOURCE_INTROSPECT = "/introspect";
    public static final String RESOURCE_TOKEN = "/token";

    public static final String JSON_CONTENT = "application/json";
    public static final String HEADER_ACCEPT = "Accept";

    public static final int HTTP_OK = 200;
    public static final int HTTP_FORBIDDEN = 403;
    public static final int HTTP_UNAUTHORIZED = 401;
}
