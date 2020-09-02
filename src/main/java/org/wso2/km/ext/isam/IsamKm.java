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
import java.util.List;
import java.util.Map;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.wso2.km.ext.isam.Constants.AUTH_HEADER;
import static org.wso2.km.ext.isam.Constants.CLIENT_ID;
import static org.wso2.km.ext.isam.Constants.CLIENT_SECRET;
import static org.wso2.km.ext.isam.Constants.ERROR_DESCRIPTION;
import static org.wso2.km.ext.isam.Constants.GRANT_TYPES;
import static org.wso2.km.ext.isam.Constants.HTTP_FORBIDDEN;
import static org.wso2.km.ext.isam.Constants.HTTP_NO_CONTENT;
import static org.wso2.km.ext.isam.Constants.HTTP_OK;
import static org.wso2.km.ext.isam.Constants.HTTP_UNAUTHORIZED;
import static org.wso2.km.ext.isam.Constants.ISAM;
import static org.wso2.km.ext.isam.Constants.JSON_CONTENT;
import static org.wso2.km.ext.isam.Constants.REDIRECT_URIS;
import static org.wso2.km.ext.isam.Constants.TOKEN_SCOPE;

public class IsamKm extends AMDefaultKeyManagerImpl {

    private static final String EMPTY_STRING = "";
    private String clientId;
    private String clientSecret;
    private int tokenLength = 0;
    boolean isTokenLength = false;
    private String tokenPrefix = null;
    private String accessToken = null;
    private String idpAttributeName;
    private BasicNameValuePair clientIdPair;
    private BasicNameValuePair clientSecretPair;

    private String tokenEndpoint;
    private String introspectionEndpoint;
    private String clientRegisterEndpoint;
    private String schema;


    @Override
    public void loadConfiguration(KeyManagerConfiguration configuration) throws APIManagementException {
        if (configuration != null) {
            if (StringUtils.isNotEmpty(configuration.getParameter(Constants.CONFIG_ISAM_ENDPOINT_URL))) {
                String isamEndpointUrl = configuration.getParameter(Constants.CONFIG_ISAM_ENDPOINT_URL);
                tokenEndpoint = isamEndpointUrl + Constants.RESOURCE_TOKEN;
                introspectionEndpoint = isamEndpointUrl + Constants.RESOURCE_INTROSPECT;
                clientRegisterEndpoint = isamEndpointUrl + Constants.RESOURCE_CLIENT_REGISTRATION;
            } else {
                throw new APIManagementException(
                        "[ISAM KM] Unable to find the <Url> property under <IsamKm> configuration.");
            }
            if (StringUtils.isNotEmpty(configuration.getParameter(Constants.CONFIG_CLIENT_ID))) {
                clientId = configuration.getParameter(Constants.CONFIG_CLIENT_ID);
            } else {
                throw new APIManagementException(
                        "[ISAM KM] Unable to find the <ClientId> property under <IsamKm> configuration.");
            }
            if (StringUtils.isNotEmpty(configuration.getParameter(Constants.CONFIG_CLIENT_SECRET))) {
                clientSecret = configuration.getParameter(Constants.CONFIG_CLIENT_SECRET);
            } else {
                throw new APIManagementException(
                        "[ISAM KM] Unable to find the <ClientSecret> property under <IsamKm> configuration.");
            }
            if (StringUtils.isNotEmpty(configuration.getParameter(Constants.CONFIG_SCHEMA))) {
                schema = configuration.getParameter(Constants.CONFIG_SCHEMA);
            } else {
                throw new APIManagementException(
                        "[ISAM KM] Unable to find the <Schema> property under <IsamKm> configuration.");
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
            }else {
                throw new APIManagementException(
                        "[ISAM KM] Unable to find the <AttributeName> property under <IsamKm> configuration. " +
                        "Please provide the same attribute name that used under ApplicationAttributes for IdP.");
            }
            clientIdPair = new BasicNameValuePair(CLIENT_ID, clientId);
            clientSecretPair = new BasicNameValuePair(CLIENT_SECRET, clientSecret);
        }
        super.loadConfiguration(configuration);
        System.setProperty("org.apache.commons.logging.Log", "org.apache.commons.logging.impl.SimpleLog");
        System.setProperty("org.apache.commons.logging.simplelog.showdatetime", "true");
        System.setProperty("org.apache.commons.logging.simplelog.log.org.apache.http.wire", "DEBUG");
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
                applicationInfo.setClientSecret(res.getString(CLIENT_SECRET));
                applicationInfo.addParameter(ApplicationConstants.OAUTH_CLIENT_SECRET, res.getString(CLIENT_SECRET));
                String tokenScope = (String) info.getParameter(TOKEN_SCOPE);
                String[] tokenScopes = new String[]{tokenScope};
                applicationInfo.addParameter(TOKEN_SCOPE, tokenScopes);
                JSONObject jsonObject = new JSONObject(info.getJsonString());
                if (jsonObject.has(GRANT_TYPES)) {
                    applicationInfo.addParameter(GRANT_TYPES, ((String) jsonObject.get(GRANT_TYPES)).
                            replace(",", " "));
                }
                if (info.getParameter(REDIRECT_URIS) != null) {
                    applicationInfo.setCallBackURL(String.valueOf(info.getParameter(REDIRECT_URIS)));
                }
                applicationInfo.addParameter(ISAM, true);
                return applicationInfo;
            } catch (JSONException e) {
                throw new APIManagementException("Unable to retrieve information from the client creation res.", e);
            }
        } else {
            return super.createApplication(oauthAppRequest);
        }
    }

    @Override
    public OAuthApplicationInfo updateApplication(OAuthAppRequest appInfoDTO) throws APIManagementException {
        OAuthApplicationInfo info = appInfoDTO.getOAuthApplicationInfo();
        Application application = getApplication(info);
        if (isISAM(application)) {
//            OAuthResponse oAuthResponse = updateApplication(application, info);
            return new OAuthApplicationInfo();
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
                applicationInfo.setClientSecret(res.getString(CLIENT_SECRET));
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
                        long expire = response.getLong(Constants.EXPIRY) * 1000;
                        long issued = response.getLong(Constants.TOKEN_ISSUED_TIME) * 1000;
                        tokenInfo.setValidityPeriod(expire - issued);
                        tokenInfo.setScope(response.getString(Constants.SCOPE).split(" "));
                        tokenInfo.setConsumerKey(response.getString(CLIENT_ID));
                        tokenInfo.setIssuedTime(issued);
                        tokenInfo.setEndUserName(response.getString(Constants.USERNAME));
//                    tokenInfo.addParameter("param1", "para1value");
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

    @Override
    public AccessTokenInfo getNewApplicationAccessToken(AccessTokenRequest tokenRequest) throws APIManagementException {
        String clientId = tokenRequest.getClientId();
        boolean isIsam = false;
        Object isIsamQueryParam = tokenRequest.getRequestParam(ISAM);
        if (isIsamQueryParam != null) {
            isIsam = (Boolean) isIsamQueryParam;
        }
        if (isIsam) {
            String clientSecret = tokenRequest.getClientSecret();
            JSONObject accessToken = getAccessToken(clientId, clientSecret);
            AccessTokenInfo accessTokenInfo = new AccessTokenInfo();
            try {
                accessTokenInfo.setAccessToken(accessToken.getString(Constants.ACCESS_TOKEN));
                accessTokenInfo.setConsumerKey(clientId);
                accessTokenInfo.setConsumerSecret(clientSecret);
                accessTokenInfo.setValidityPeriod(accessToken.getLong("expires_in"));
            } catch (JSONException e) {
                throw new APIManagementException("Unable to retrieve information from token response", e);
            }
            return accessTokenInfo;
        }
        return super.getNewApplicationAccessToken(tokenRequest);
    }

    @Override
    public AccessTokenRequest buildAccessTokenRequestFromOAuthApp(OAuthApplicationInfo oAuthApplication,
                                                                  AccessTokenRequest tokenRequest)
            throws APIManagementException {
        AccessTokenRequest req = super.buildAccessTokenRequestFromOAuthApp(oAuthApplication, tokenRequest);
        if (Boolean.TRUE.equals(oAuthApplication.getParameter(ISAM))) {
            req.addRequestParam(ISAM, true);
        }
        return req;
    }

    private Application getApplication(OAuthApplicationInfo oAuthApplicationInfo) throws APIManagementException {
        ApiMgtDAO dao = ApiMgtDAO.getInstance();
        String clientId = oAuthApplicationInfo.getClientName();
        String userId = (String) oAuthApplicationInfo.getParameter(ApplicationConstants.OAUTH_CLIENT_USERNAME);
        return dao.getApplicationByName(clientId, userId, null);
    }

    private OAuthResponse executeHttpMethod(HttpRequestBase method) throws APIManagementException {
        CloseableHttpClient client = HttpClientBuilder.create().build();
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
            if (accessToken == null) {
                accessToken = getAccessToken(this.clientId, clientSecret).getString(Constants.ACCESS_TOKEN);
            }
            HttpPost post = getCreateApplicationPostMethod(application, info);
            OAuthResponse res = executeHttpMethod(post);
            if (res.getStatusCode() == HTTP_UNAUTHORIZED || res.getStatusCode() == HTTP_FORBIDDEN) {
                accessToken = getAccessToken(this.clientId, clientSecret).getString(Constants.ACCESS_TOKEN);
                post.releaseConnection();
                post.setHeader(AUTH_HEADER, getAuthorizationHeaderForAccessToken());
                res = executeHttpMethod(post);
            }
            if (res.getStatusCode() != HTTP_OK) {
                throw new APIManagementException(
                        "Could not create application successfully in the ISAM. ISAM respond with " +
                                res.getStatusCode() + ", Error: " + getErrorDescription(res));
            }
            return res;
        } catch (JSONException e) {
            throw new APIManagementException("Could not create the application.", e);
        }
    }

    private OAuthResponse updateApplication(Application application, OAuthApplicationInfo info)
            throws APIManagementException {
        try {
            if (accessToken == null) {
                accessToken = getAccessToken(this.clientId, clientSecret).getString(Constants.ACCESS_TOKEN);
            }
            HttpPut put = getUpdateApplicationPutMethod(application, info);
            OAuthResponse res = executeHttpMethod(put);
            if (res.getStatusCode() == HTTP_UNAUTHORIZED || res.getStatusCode() == HTTP_FORBIDDEN) {
                accessToken = getAccessToken(this.clientId, clientSecret).getString(Constants.ACCESS_TOKEN);
                put.releaseConnection();
                put.setHeader(AUTH_HEADER, getAuthorizationHeaderForAccessToken());
                res = executeHttpMethod(put);
            }
            if (res.getStatusCode() != HTTP_OK) {
                throw new APIManagementException(
                        "Could not create application successfully in the ISAM. ISAM respond with " +
                                res.getStatusCode() + ", Error: " + getErrorDescription(res));
            }
            return res;
        } catch (JSONException e) {
            throw new APIManagementException("Could not create the application.", e);
        }
    }

    private void deleteISAMApplication(String clientId) throws APIManagementException {
        try {
            if (accessToken == null) {
                accessToken = getAccessToken(this.clientId, clientSecret).getString(Constants.ACCESS_TOKEN);
            }
            HttpDelete delete = getDeleteApplicationDeleteMethod(clientId);
            OAuthResponse response = executeHttpMethod(delete);
            if (response.getStatusCode() == HTTP_UNAUTHORIZED || response.getStatusCode() == HTTP_FORBIDDEN) {
                accessToken = getAccessToken(this.clientId, clientSecret).getString(Constants.ACCESS_TOKEN);
                delete.releaseConnection();
                delete.setHeader(AUTH_HEADER, getAuthorizationHeaderForAccessToken());
                response = executeHttpMethod(delete);
            }
            if (!(response.getStatusCode() == HTTP_NO_CONTENT || response.getStatusCode() == HTTP_OK)) {
                throw new APIManagementException(
                        "Could not delete the application from ISAM. ISAM respond with  " + response.getStatusCode() +
                                ", Error: " + getErrorDescription(response));
            }
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
            if (accessToken == null) {
                accessToken = getAccessToken(this.clientId, clientSecret).getString(Constants.ACCESS_TOKEN);
            }
            HttpGet get = getRetrieveApplicationGetMethod(clientId);
            OAuthResponse res = executeHttpMethod(get);
            if (res.getStatusCode() == HTTP_UNAUTHORIZED || res.getStatusCode() == HTTP_FORBIDDEN) {
                accessToken = getAccessToken(this.clientId, clientSecret).getString(Constants.ACCESS_TOKEN);
                get.releaseConnection();
                get.setHeader(AUTH_HEADER, getAuthorizationHeaderForAccessToken());
                res = executeHttpMethod(get);
            }
            if (res.getStatusCode() != HTTP_OK) {
                throw new APIManagementException(
                        "Could not retrieve application details from the ISAM. ISAM respond with " +
                                res.getStatusCode() + ", Error: " + getErrorDescription(res));
            }
            return res;
        } catch (JSONException e) {
            throw new APIManagementException("Could not retrieve application details.", e);
        }
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
        String url = clientRegisterEndpoint + "/" + schema;
        HttpPost post = new HttpPost(url);
        post.addHeader(AUTH_HEADER, getAuthorizationHeaderForAccessToken());
        post.setEntity(getCreateApplicationPayloadEntity(application, info));
        return post;
    }

    private HttpPut getUpdateApplicationPutMethod(Application application, OAuthApplicationInfo info)
            throws JSONException {
        String url = clientRegisterEndpoint + "/" + schema;
        HttpPut put = new HttpPut(url);
        put.addHeader(AUTH_HEADER, getAuthorizationHeaderForAccessToken());
        put.setEntity(getCreateApplicationPayloadEntity(application, info));
        return put;
    }

    private HttpDelete getDeleteApplicationDeleteMethod(String clientId) {
        String url = clientRegisterEndpoint + "/" + schema + "?client_id=" + clientId;
        HttpDelete delete = new HttpDelete(url);
        delete.addHeader(AUTH_HEADER, getAuthorizationHeaderForAccessToken());
        return delete;
    }

    private HttpGet getRetrieveApplicationGetMethod(String clientId) {
        String url = clientRegisterEndpoint + "/" + schema + "?client_id=" + clientId;
        HttpGet get = new HttpGet(url);
        get.addHeader(AUTH_HEADER, getAuthorizationHeaderForAccessToken());
        return get;
    }

    private HttpPost getAccessTokenPostMethod(String clientId, String clientSecret) {
        HttpPost post = new HttpPost(tokenEndpoint);
        post.setEntity(getAccessTokenPayloadEntity(clientId, clientSecret));
        return post;
    }

    private HttpPost getIntrospectionPostMethod(String token) {
        HttpPost post = new HttpPost(introspectionEndpoint);
        post.setEntity(getIntrospectionPayloadEntity(token));
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
        parametersBody.add(clientIdPair);
        parametersBody.add(clientSecretPair);
        parametersBody.add(new BasicNameValuePair(Constants.TOKEN, token));
        return new UrlEncodedFormEntity(parametersBody, UTF_8);
    }

    private String getAuthorizationHeaderForAccessToken() {
        return Constants.BEARER + " " + accessToken;
    }

    private boolean isISAM(Application application) {
        if (application != null) {
            String idp = application.getApplicationAttributes().get(idpAttributeName);
            return ISAM.equalsIgnoreCase(idp);
        }
        return false;
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
}
