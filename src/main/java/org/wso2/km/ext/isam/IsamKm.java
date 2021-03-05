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

import org.apache.commons.lang.StringUtils;
import org.apache.http.HttpEntity;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpDelete;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpPut;
import org.apache.http.client.methods.HttpRequestBase;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.util.EntityUtils;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.wso2.carbon.apimgt.api.APIManagementException;
import org.wso2.carbon.apimgt.api.model.AccessTokenInfo;
import org.wso2.carbon.apimgt.api.model.AccessTokenRequest;
import org.wso2.carbon.apimgt.api.model.Application;
import org.wso2.carbon.apimgt.api.model.ApplicationConstants;
import org.wso2.carbon.apimgt.api.model.KeyManagerConfiguration;
import org.wso2.carbon.apimgt.api.model.OAuthAppRequest;
import org.wso2.carbon.apimgt.api.model.OAuthApplicationInfo;
import org.wso2.carbon.apimgt.impl.AMDefaultKeyManagerImpl;
import org.wso2.carbon.apimgt.impl.dao.ApiMgtDAO;
import org.wso2.carbon.apimgt.impl.utils.APIMgtDBUtil;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.wso2.carbon.apimgt.api.model.ApplicationConstants.OAUTH_CLIENT_USERNAME;
import static org.wso2.km.ext.isam.Constants.ACTIVE;
import static org.wso2.km.ext.isam.Constants.AUTH_HEADER;
import static org.wso2.km.ext.isam.Constants.CLIENT_ID;
import static org.wso2.km.ext.isam.Constants.CLIENT_SECRET;
import static org.wso2.km.ext.isam.Constants.ERROR_DESCRIPTION;
import static org.wso2.km.ext.isam.Constants.EXPIRY;
import static org.wso2.km.ext.isam.Constants.HTTP_FORBIDDEN;
import static org.wso2.km.ext.isam.Constants.HTTP_NO_CONTENT;
import static org.wso2.km.ext.isam.Constants.HTTP_OK;
import static org.wso2.km.ext.isam.Constants.HTTP_UNAUTHORIZED;
import static org.wso2.km.ext.isam.Constants.ISAM;
import static org.wso2.km.ext.isam.Constants.ISAM_SCOPES;
import static org.wso2.km.ext.isam.Constants.IS_PKCE;
import static org.wso2.km.ext.isam.Constants.JSON_CONTENT;
import static org.wso2.km.ext.isam.Constants.REDIRECT_URIS;
import static org.wso2.km.ext.isam.Constants.SCOPE;
import static org.wso2.km.ext.isam.Constants.TOKEN_ISSUED_TIME;
import static org.wso2.km.ext.isam.Constants.USERNAME;

public class IsamKm extends AMDefaultKeyManagerImpl {

    private static final String EMPTY_STRING = "";
    private String clientId;
    private String clientSecret;
    private String basicAuthToken;
    private String basicAuthHeader;
    private int tokenLength = 0;
    boolean isTokenLength = false;
    boolean isClientCredentials = false;
    boolean isBasicAuth = false;
    private String tokenPrefix = null;
    private String accessToken = null;
    private String idpAttributeName;
    private BasicNameValuePair clientIdPair;
    private BasicNameValuePair clientSecretPair;

    private CloseableHttpClient client;
    private String tokenEndpoint;
    private String introspectionEndpoint;
    private String clientRegisterEndpoint;
    private String userStorePrefix = null;
    private final List<String> introspectionDefaultResultKeys = new ArrayList<>();


    @Override
    public void loadConfiguration(KeyManagerConfiguration configuration) throws APIManagementException {
        if (configuration != null) {
            if (StringUtils.isNotEmpty(configuration.getParameter(Constants.CONFIG_ISAM_ENDPOINT_URL))) {
                String isamEndpointUrl = configuration.getParameter(Constants.CONFIG_ISAM_ENDPOINT_URL);
                tokenEndpoint = isamEndpointUrl + Constants.RESOURCE_TOKEN;
                introspectionEndpoint = isamEndpointUrl + Constants.RESOURCE_INTROSPECT;
            } else {
                throw new APIManagementException(
                        "[ISAM KM] Unable to find the <Url> property under <IsamKm> configuration.");
            }
            if (StringUtils.isNotEmpty(configuration.getParameter(Constants.CONFIG_CLIENT_ID))) {
                clientId = configuration.getParameter(Constants.CONFIG_CLIENT_ID);
                isClientCredentials = true;
            }
            if (StringUtils.isNotEmpty(configuration.getParameter(Constants.CONFIG_CLIENT_SECRET))) {
                clientSecret = configuration.getParameter(Constants.CONFIG_CLIENT_SECRET);
            }
            if (StringUtils.isNotEmpty(configuration.getParameter(Constants.CONFIG_BASIC_AUTH_TOKEN))) {
                basicAuthToken = configuration.getParameter(Constants.CONFIG_BASIC_AUTH_TOKEN);
                basicAuthHeader = Constants.BASIC + " " + basicAuthToken;
                isBasicAuth = true;
            }
            if (basicAuthToken == null && (clientId == null || clientSecret == null)) {
                throw new APIManagementException(
                        "[ISAM KM] Unable to find the <ClientId> and <ClientSecret> properties OR <BasicAuth> " +
                                "property under <IsamKm> configuration.");
            }
            if (StringUtils.isNotEmpty(configuration.getParameter(Constants.CONFIG_DEFINITION))) {
                String definition = configuration.getParameter(Constants.CONFIG_DEFINITION);
                String isamEndpointUrl = configuration.getParameter(Constants.CONFIG_ISAM_ENDPOINT_URL);
                clientRegisterEndpoint = isamEndpointUrl + Constants.RESOURCE_CLIENT_REGISTRATION + "/" + definition;
            } else {
                throw new APIManagementException(
                        "[ISAM KM] Unable to find the <Definition> property under <IsamKm> configuration.");
            }
            if (StringUtils.isNotEmpty(configuration.getParameter(Constants.CONFIG_TOKEN_LENGTH))) {
                tokenLength = Integer.parseInt(configuration.getParameter(Constants.CONFIG_TOKEN_LENGTH));
                isTokenLength = true;
            }
            if (StringUtils.isNotEmpty(configuration.getParameter(Constants.CONFIG_TOKEN_PREFIX))) {
                tokenPrefix = configuration.getParameter(Constants.CONFIG_TOKEN_PREFIX);
            }
            if (tokenLength == 0 && tokenPrefix == null) {
                throw new APIManagementException(
                        "[ISAM KM] Unable to find the <TokenLength> or <TokenPrefix> property under <IsamKm> " +
                                "configuration.");
            }
            if (StringUtils.isNotEmpty(configuration.getParameter(Constants.CONFIG_ATTRIBUTE_NAME))) {
                idpAttributeName = configuration.getParameter(Constants.CONFIG_ATTRIBUTE_NAME);
            } else {
                throw new APIManagementException(
                        "[ISAM KM] Unable to find the <AttributeName> property under <IsamKm> configuration. " +
                                "Please provide the same attribute name that used under ApplicationAttributes for IdP" +
                                ".");
            }
            clientIdPair = new BasicNameValuePair(CLIENT_ID, clientId);
            clientSecretPair = new BasicNameValuePair(CLIENT_SECRET, clientSecret);
            int maxConnPerRoute = 50;
            int maxConnTotal = 100;
            if (StringUtils.isNotEmpty(configuration.getParameter(Constants.MAX_CONN_PER_ROUTE))) {
                maxConnPerRoute = Integer.parseInt(configuration.getParameter(Constants.MAX_CONN_PER_ROUTE));
            }
            if (StringUtils.isNotEmpty(configuration.getParameter(Constants.MAX_CONN_TOTAL))) {
                maxConnTotal = Integer.parseInt(configuration.getParameter(Constants.MAX_CONN_TOTAL));
            }
            if (StringUtils.isNotEmpty(configuration.getParameter(Constants.USER_STORE_PREFIX))) {
                userStorePrefix = configuration.getParameter(Constants.USER_STORE_PREFIX);
            }
            client = HttpClientBuilder.create().setMaxConnPerRoute(maxConnPerRoute).setMaxConnTotal(maxConnTotal)
                    .disableCookieManagement().build();
        }
        super.loadConfiguration(configuration);
        populateDefaultIntrospectionProperties();
        System.setProperty("org.apache.commons.logging.Log", "org.apache.commons.logging.impl.SimpleLog");
        System.setProperty("org.apache.commons.logging.simplelog.showdatetime", "true");
        System.setProperty("org.apache.commons.logging.simplelog.log.org.apache.http.wire", "DEBUG");
    }

    private void populateDefaultIntrospectionProperties() {
        introspectionDefaultResultKeys.add(SCOPE);
        introspectionDefaultResultKeys.add(ACTIVE);
        introspectionDefaultResultKeys.add(Constants.TOKEN_TYPE);
        introspectionDefaultResultKeys.add(EXPIRY);
        introspectionDefaultResultKeys.add(TOKEN_ISSUED_TIME);
        introspectionDefaultResultKeys.add(CLIENT_ID);
        introspectionDefaultResultKeys.add(USERNAME);
    }

    @Override
    public OAuthApplicationInfo createApplication(OAuthAppRequest oauthAppRequest) throws APIManagementException {
        OAuthApplicationInfo info = oauthAppRequest.getOAuthApplicationInfo();
        Application application = getApplication(info);
        if (isISAM(application)) {
            JSONObject res = createApplication(application, info).getResponse();
            try {
                OAuthApplicationInfo applicationInfo = new OAuthApplicationInfo();
                applicationInfo.setClientName(info.getClientName());
                applicationInfo.addParameter(ApplicationConstants.OAUTH_CLIENT_NAME, info.getClientName());
                applicationInfo.setClientId(res.getString(CLIENT_ID));
                applicationInfo.addParameter(ApplicationConstants.OAUTH_CLIENT_ID, res.getString(CLIENT_ID));
                if (res.has(CLIENT_SECRET)) {
                    applicationInfo.setClientSecret(res.getString(CLIENT_SECRET));
                    applicationInfo.addParameter(ApplicationConstants.OAUTH_CLIENT_SECRET,
                                                 res.getString(CLIENT_SECRET));
                }
                //applicationInfo.addParameter(GRANT_TYPES, APIConstants.GRANT_TYPE_CLIENT_CREDENTIALS);
                if (info.getParameter(REDIRECT_URIS) != null) {
                    applicationInfo.setCallBackURL(String.valueOf(info.getParameter(REDIRECT_URIS)));
                }
                return applicationInfo;
            } catch (JSONException e) {
                throw new APIManagementException("Unable to retrieve information from the client creation response.",
                                                 e);
            }
        } else {
            return super.createApplication(oauthAppRequest);
        }
    }

    @Override
    public OAuthApplicationInfo updateApplication(OAuthAppRequest appInfoDTO) throws APIManagementException {
        OAuthApplicationInfo info = appInfoDTO.getOAuthApplicationInfo();
        String idp = getIDPNameByClientId(info.getClientId());
        if (ISAM.equalsIgnoreCase(idp)) {
            try {
                Application application = getApplication(info);
                if (getISAMApplication(info.getClientId()).getResponse().has(CLIENT_SECRET)) {
                    info.setClientSecret(getISAMApplication(info.getClientId()).getResponse().getString(CLIENT_SECRET));
                }
                JSONObject res = updateApplication(application, info).getResponse();
                OAuthApplicationInfo applicationInfo = new OAuthApplicationInfo();
                applicationInfo.setClientName(info.getClientName());
                applicationInfo.addParameter(ApplicationConstants.OAUTH_CLIENT_NAME, info.getClientName());
                applicationInfo.setClientId(res.getString(CLIENT_ID));
                applicationInfo.addParameter(ApplicationConstants.OAUTH_CLIENT_ID, res.getString(CLIENT_ID));
                if (res.has(CLIENT_SECRET)) {
                    applicationInfo.setClientSecret(res.getString(CLIENT_SECRET));
                    applicationInfo.addParameter(ApplicationConstants.OAUTH_CLIENT_SECRET,
                                                 res.getString(CLIENT_SECRET));
                }
                //applicationInfo.addParameter(GRANT_TYPES, APIConstants.GRANT_TYPE_CLIENT_CREDENTIALS);
                if (info.getCallBackURL() != null) {
                    applicationInfo.setCallBackURL(info.getCallBackURL());
                }
                return applicationInfo;
            } catch (JSONException e) {
                throw new APIManagementException("Unable to retrieve information from the client update response.", e);
            }
        } else {
            return super.updateApplication(appInfoDTO);
        }
    }

    @Override
    public OAuthApplicationInfo retrieveApplication(String consumerKey) throws APIManagementException {
        String idp = getIDPNameByClientId(consumerKey);
        if (ISAM.equalsIgnoreCase(idp)) {
            try {
                JSONObject res = getISAMApplication(consumerKey).getResponse();
                OAuthApplicationInfo applicationInfo = new OAuthApplicationInfo();
                applicationInfo.setClientId(res.getString(CLIENT_ID));
                if (res.has(CLIENT_SECRET)) {
                    applicationInfo.setClientSecret(res.getString(CLIENT_SECRET));
                }
                applicationInfo.setCallBackURL(res.getJSONArray(REDIRECT_URIS).getString(0));
                JSONArray redirectUris = res.getJSONArray(REDIRECT_URIS);
                StringBuilder uris = new StringBuilder();
                for (int i = 0; i < redirectUris.length(); i++) {
                    uris.append(redirectUris.getString(i));
                    uris.append(",");
                }
                if (uris.length() > 0) {
                    uris.deleteCharAt(uris.length() - 1);
                }
                applicationInfo.addParameter(REDIRECT_URIS, uris.toString());
                //applicationInfo.addParameter(GRANT_TYPES, APIConstants.GRANT_TYPE_CLIENT_CREDENTIALS);
                return applicationInfo;
            } catch (JSONException e) {
                throw new APIManagementException("Unable to retrieve information from the client details response.", e);
            }
        } else {
            return super.retrieveApplication(consumerKey);
        }
    }

    @Override
    public void deleteApplication(String consumerKey) throws APIManagementException {
        String idp = getIDPNameByClientId(consumerKey);
        if (ISAM.equalsIgnoreCase(idp)) {
            deleteISAMApplication(consumerKey);
        } else {
            super.deleteApplication(consumerKey);
        }
    }

    @Override
    public AccessTokenInfo getTokenMetaData(String accessToken) throws APIManagementException {
        if (isIsamToken(accessToken)) {
            try {
                OAuthResponse res = sendIntrospection(accessToken);
                if (res.getStatusCode() == HTTP_OK) {
                    JSONObject response = res.getResponse();
                    AccessTokenInfo tokenInfo = new AccessTokenInfo();
                    boolean isActive = response.getBoolean(Constants.ACTIVE);
                    tokenInfo.setTokenValid(isActive);
                    if (isActive) {
                        long expire = response.getLong(EXPIRY) * 1000;
                        long issued = response.getLong(TOKEN_ISSUED_TIME) * 1000;
                        tokenInfo.setValidityPeriod(expire - issued);
                        tokenInfo.setScope(response.getString(SCOPE).split(" "));
                        tokenInfo.addParameter(ISAM_SCOPES, response.getString(SCOPE).split(" "));
                        tokenInfo.setConsumerKey(response.getString(CLIENT_ID));
                        tokenInfo.setIssuedTime(issued);
                        tokenInfo.setEndUserName((userStorePrefix == null) ? response.getString(USERNAME) :
                                                         userStorePrefix + "/" + response.getString(USERNAME));
                        Iterator keys = response.keys();
                        while (keys.hasNext()) {
                            String id = (String) keys.next();
                            if (!isDefaultProperty(id)) {
                                tokenInfo.addParameter(id, response.getString(id));
                            }
                        }
                    }
                    return tokenInfo;
                } else {
                    throw new APIManagementException(
                            "ISAM introspection endpoint respond with " + res.getStatusCode() +
                                    ", Error: " + getErrorDescription(res));
                }
            } catch (JSONException e) {
                throw new APIManagementException(e);
            }
        } else {
            return super.getTokenMetaData(accessToken);
        }
    }

    private boolean isDefaultProperty(String id) {
        return introspectionDefaultResultKeys.contains(id);
    }

    @Override
    public AccessTokenInfo getNewApplicationAccessToken(AccessTokenRequest tokenRequest) throws APIManagementException {
        String clientId = tokenRequest.getClientId();
        String idp = getIDPNameByClientId(clientId);
        if (ISAM.equalsIgnoreCase(idp)) {
            String clientSecret = tokenRequest.getClientSecret();
            JSONObject accessToken = getAccessToken(clientId, clientSecret);
            AccessTokenInfo accessTokenInfo = new AccessTokenInfo();
            try {
                accessTokenInfo.setAccessToken(accessToken.getString(Constants.ACCESS_TOKEN));
                accessTokenInfo.setConsumerKey(clientId);
                accessTokenInfo.setConsumerSecret(clientSecret);
                accessTokenInfo.setValidityPeriod(accessToken.getLong("expires_in"));
                accessTokenInfo.setTokenValid(true);
                accessTokenInfo.setTokenState("active");
            } catch (JSONException e) {
                throw new APIManagementException("Unable to retrieve information from token response", e);
            }
            return accessTokenInfo;
        }
        return super.getNewApplicationAccessToken(tokenRequest);
    }

    private Application getApplication(OAuthApplicationInfo oAuthApplicationInfo) throws APIManagementException {
        ApiMgtDAO dao = ApiMgtDAO.getInstance();
        String clientId = oAuthApplicationInfo.getClientName();
        String userId = (String) oAuthApplicationInfo.getParameter(OAUTH_CLIENT_USERNAME);
        return dao.getApplicationByName(clientId, userId, null);
    }

    private OAuthResponse executeHttpMethod(HttpRequestBase method) throws APIManagementException {
        method.addHeader(Constants.HEADER_ACCEPT, JSON_CONTENT);
        try (CloseableHttpResponse response = client.execute(method)) {
            int statusCode = response.getStatusLine().getStatusCode();
            JSONObject responseJson = null;
            if (statusCode != HTTP_NO_CONTENT) {
                HttpEntity entity = response.getEntity();
                responseJson = new JSONObject(EntityUtils.toString(entity, UTF_8));
                EntityUtils.consumeQuietly(entity);
            }
            return new OAuthResponse(statusCode, responseJson);
        } catch (JSONException e) {
            throw new APIManagementException("Malformed JSON response from " + method.getURI().getPath(), e);
        } catch (Exception e) {
            throw new APIManagementException("Could not retrieve response from " + method.getURI().getPath(), e);
        }
    }

    private OAuthResponse createApplication(Application application, OAuthApplicationInfo info)
            throws APIManagementException {
        try {
            createAccessTokenIfNeed();
            HttpPost post = getCreateApplicationPostMethod(application, info);
            String errorMsg = "Could not create application successfully in the ISAM. ISAM respond with ";
            return getOAuthResponse(post, errorMsg, false);
        } catch (JSONException e) {
            throw new APIManagementException("Could not create the application.", e);
        }
    }

    private OAuthResponse updateApplication(Application application, OAuthApplicationInfo info)
            throws APIManagementException {
        try {
            createAccessTokenIfNeed();
            HttpPut put = getUpdateApplicationPutMethod(application, info);
            String errorMsg = "Could not update application successfully in the ISAM. ISAM respond with ";
            return getOAuthResponse(put, errorMsg, false);
        } catch (JSONException e) {
            throw new APIManagementException("Could not create the application.", e);
        }
    }

    private void deleteISAMApplication(String clientId) throws APIManagementException {
        try {
            createAccessTokenIfNeed();
            HttpDelete delete = getDeleteApplicationDeleteMethod(clientId);
            String errorMsg = "Could not delete the application from ISAM. ISAM respond with  ";
            getOAuthResponse(delete, errorMsg, true);
        } catch (JSONException e) {
            throw new APIManagementException("Could not delete the application.", e);
        }
    }

    private OAuthResponse sendIntrospection(String token) throws APIManagementException {
        HttpPost post = getIntrospectionPostMethod(token);
        return executeHttpMethod(post);
    }

    private OAuthResponse getISAMApplication(String clientId) throws APIManagementException {
        try {
            createAccessTokenIfNeed();
            HttpGet get = getRetrieveApplicationGetMethod(clientId);
            String errorMsg = "Could not retrieve application details from the ISAM. ISAM respond with ";
            return getOAuthResponse(get, errorMsg, false);
        } catch (JSONException e) {
            throw new APIManagementException("Could not retrieve application details.", e);
        }
    }

    private void createAccessTokenIfNeed() throws JSONException, APIManagementException {
        // Priority is given in an event of both basic auth and clientCredentials present situation.
        if (!isBasicAuth && isClientCredentials && accessToken == null) {
            accessToken = getAccessToken(clientId, clientSecret).getString(Constants.ACCESS_TOKEN);
        }
    }

    private OAuthResponse getOAuthResponse(HttpRequestBase method, String errorMsg, boolean isDelete)
            throws APIManagementException,
                   JSONException {
        OAuthResponse res = executeHttpMethod(method);
        if (!isBasicAuth && isClientCredentials &&
                (res.getStatusCode() == HTTP_UNAUTHORIZED || res.getStatusCode() == HTTP_FORBIDDEN)) {
            accessToken = getAccessToken(clientId, clientSecret).getString(Constants.ACCESS_TOKEN);
            method.setHeader(AUTH_HEADER, getAuthorizationHeaderForAccessToken());
            res = executeHttpMethod(method);
        }
        if (isDelete) {
            if (!(res.getStatusCode() == HTTP_NO_CONTENT || res.getStatusCode() == HTTP_OK)) {
                throw new APIManagementException(
                        errorMsg + res.getStatusCode() + ", Error: " + getErrorDescription(res));
            }
        } else {
            if (res.getStatusCode() != HTTP_OK) {
                throw new APIManagementException(
                        errorMsg + res.getStatusCode() + ", Error: " + getErrorDescription(res));
            }
        }
        return res;
    }

    private JSONObject getAccessToken(String clientId, String clientSecret) throws APIManagementException {
        try {
            HttpPost post = getAccessTokenPostMethod(clientId, clientSecret);
            OAuthResponse res = executeHttpMethod(post);
            if (res.getStatusCode() == 200) {
                return res.getResponse();
            } else {
                throw new APIManagementException(
                        "Could not retrieve access token for client: " + clientId + ". Endpoint respond with " +
                                res.getStatusCode() + ", Error: " + getErrorDescription(res));
            }
        } catch (JSONException e) {
            throw new APIManagementException("access_token entry not available in the response.", e);
        }
    }

    private HttpPost getCreateApplicationPostMethod(Application application, OAuthApplicationInfo info)
            throws JSONException {
        HttpPost post = new HttpPost(clientRegisterEndpoint);
        setAuthHeader(post);
        post.setEntity(getCreateApplicationPayloadEntity(application, info));
        return post;
    }

    private HttpPut getUpdateApplicationPutMethod(Application application, OAuthApplicationInfo info)
            throws JSONException {
        String url = clientRegisterEndpoint + "?client_id=" + info.getClientId();
        HttpPut put = new HttpPut(url);
        setAuthHeader(put);
        put.setEntity(getUpdateApplicationPayloadEntity(application, info));
        return put;
    }

    private HttpDelete getDeleteApplicationDeleteMethod(String clientId) {
        String url = clientRegisterEndpoint + "?client_id=" + clientId;
        HttpDelete delete = new HttpDelete(url);
        setAuthHeader(delete);
        return delete;
    }

    private HttpGet getRetrieveApplicationGetMethod(String clientId) {
        String url = clientRegisterEndpoint + "?client_id=" + clientId;
        HttpGet get = new HttpGet(url);
        setAuthHeader(get);
        return get;
    }

    private void setAuthHeader(HttpRequestBase method) {
        if (isBasicAuth) {
            method.addHeader(AUTH_HEADER, getAuthorizationHeaderForBasicAuth());
        } else {
            method.addHeader(AUTH_HEADER, getAuthorizationHeaderForAccessToken());
        }
    }

    private HttpPost getAccessTokenPostMethod(String clientId, String clientSecret) {
        HttpPost post = new HttpPost(tokenEndpoint);
        post.setEntity(getAccessTokenPayloadEntity(clientId, clientSecret));
        return post;
    }

    private HttpPost getIntrospectionPostMethod(String token) {
        HttpPost post = new HttpPost(introspectionEndpoint);
        post.setEntity(getIntrospectionPayloadEntity(token));
        if (!isClientCredentials) {
            post.addHeader(AUTH_HEADER, getAuthorizationHeaderForBasicAuth());
        }
        return post;
    }

    private StringEntity getCreateApplicationPayloadEntity(Application application, OAuthApplicationInfo info)
            throws JSONException {
        JSONObject jsonPayload = new JSONObject();
        for (Map.Entry<String, String> entry : application.getApplicationAttributes().entrySet()) {
            jsonPayload.put(entry.getKey(), entry.getValue());
        }
        JSONArray redirectsUris = new JSONArray();
        String callbackUrls = (String) info.getParameter(Constants.CALLBACK_URL);
        if (callbackUrls != null && !callbackUrls.isEmpty()) {
            String[] urls = callbackUrls.split(",");
            for (String url : urls) {
                redirectsUris.put(url.trim());
            }
        }
        jsonPayload.put(REDIRECT_URIS, redirectsUris);
        jsonPayload.put(IS_PKCE, true);
        StringEntity entity = new StringEntity(jsonPayload.toString(), UTF_8);
        entity.setContentType(JSON_CONTENT);
        return entity;
    }

    private StringEntity getUpdateApplicationPayloadEntity(Application application, OAuthApplicationInfo info)
            throws JSONException {
        JSONObject jsonPayload = new JSONObject();
        for (Map.Entry<String, String> entry : application.getApplicationAttributes().entrySet()) {
            jsonPayload.put(entry.getKey(), entry.getValue());
        }
        JSONArray redirectsUris = new JSONArray();
        String callbackUrls = info.getCallBackURL();
        if (callbackUrls != null && !callbackUrls.isEmpty()) {
            String[] urls = callbackUrls.split(",");
            for (String url : urls) {
                redirectsUris.put(url.trim());
            }
        }
        jsonPayload.put(CLIENT_ID, info.getClientId());
        if (info.getClientSecret() != null) {
            jsonPayload.put(CLIENT_SECRET, info.getClientSecret());
        }
        jsonPayload.put(REDIRECT_URIS, redirectsUris);
        jsonPayload.put(IS_PKCE, true);
        StringEntity entity = new StringEntity(jsonPayload.toString(), UTF_8);
        entity.setContentType(JSON_CONTENT);
        return entity;
    }

    private UrlEncodedFormEntity getAccessTokenPayloadEntity(String clientId, String clientSecret) {
        List<BasicNameValuePair> parametersBody = new ArrayList<>(7);
        parametersBody.add(new BasicNameValuePair(Constants.GRANT_TYPE, Constants.GRANT_CLIENT_CREDENTIALS));
        parametersBody.add(new BasicNameValuePair(CLIENT_ID, clientId));
        parametersBody.add(new BasicNameValuePair(CLIENT_SECRET, clientSecret));
        parametersBody.add(new BasicNameValuePair(Constants.TOKEN_TYPE_HINT, Constants.ACCESS_TOKEN));
        return new UrlEncodedFormEntity(parametersBody, UTF_8);
    }

    private UrlEncodedFormEntity getIntrospectionPayloadEntity(String token) {
        List<BasicNameValuePair> parametersBody = new ArrayList<>(5);
        if (isClientCredentials) {
            parametersBody.add(clientIdPair);
            parametersBody.add(clientSecretPair);
        }
        parametersBody.add(new BasicNameValuePair(Constants.TOKEN, token));
        return new UrlEncodedFormEntity(parametersBody, UTF_8);
    }

    private String getAuthorizationHeaderForAccessToken() {
        return Constants.BEARER + " " + accessToken;
    }

    private String getAuthorizationHeaderForBasicAuth() {
        return basicAuthHeader;
    }

    private String getIDPNameByClientId(String clientId) throws APIManagementException {
        Connection connection = null;
        PreparedStatement prepStmt = null;
        ResultSet rs = null;
        try {
            connection = APIMgtDBUtil.getConnection();
            String query =
                    "SELECT ATTRIBUTE.VALUE " +
                            "FROM AM_APPLICATION_KEY_MAPPING AM_APP_MAP, AM_APPLICATION_ATTRIBUTES ATTRIBUTE " +
                            "WHERE AM_APP_MAP.CONSUMER_KEY = ? AND ATTRIBUTE.NAME = ? AND " +
                            "AM_APP_MAP.APPLICATION_ID = ATTRIBUTE.APPLICATION_ID";
            prepStmt = connection.prepareStatement(query);
            prepStmt.setString(1, clientId);
            prepStmt.setString(2, idpAttributeName);
            rs = prepStmt.executeQuery();
            if (rs.next()) {
                return rs.getString("VALUE");
            }
        } catch (SQLException e) {
            throw new APIManagementException(
                    "Error while obtaining details of the Application for client id " + clientId, e);
        } finally {
            APIMgtDBUtil.closeAllConnections(prepStmt, connection, rs);
        }
        return null;
    }

    private String getErrorDescription(OAuthResponse res) throws JSONException {
        return res.getResponse().has(ERROR_DESCRIPTION) ? res.getResponse().getString(ERROR_DESCRIPTION) : EMPTY_STRING;
    }

    private boolean isIsamToken(String accessToken) {
        if (isTokenLength) {
            return tokenLength == accessToken.length();
        }
        return accessToken.startsWith(tokenPrefix);
    }

    private boolean isISAM(Application application) {
        if (application != null) {
            String idp = application.getApplicationAttributes().get(idpAttributeName);
            return ISAM.equalsIgnoreCase(idp);
        }
        return false;
    }
}
