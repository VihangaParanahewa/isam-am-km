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
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.HttpEntity;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpDelete;
import org.apache.http.client.methods.HttpPost;
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
import org.wso2.carbon.apimgt.api.model.Application;
import org.wso2.carbon.apimgt.api.model.ApplicationConstants;
import org.wso2.carbon.apimgt.api.model.KeyManagerConfiguration;
import org.wso2.carbon.apimgt.api.model.OAuthAppRequest;
import org.wso2.carbon.apimgt.api.model.OAuthApplicationInfo;
import org.wso2.carbon.apimgt.impl.AMDefaultKeyManagerImpl;
import org.wso2.carbon.apimgt.impl.dao.ApiMgtDAO;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.wso2.km.ext.isam.Constants.AUTH_HEADER;
import static org.wso2.km.ext.isam.Constants.CLIENT_ID;
import static org.wso2.km.ext.isam.Constants.CLIENT_SECRET;
import static org.wso2.km.ext.isam.Constants.ERROR_DESCRIPTION;
import static org.wso2.km.ext.isam.Constants.HTTP_FORBIDDEN;
import static org.wso2.km.ext.isam.Constants.HTTP_OK;
import static org.wso2.km.ext.isam.Constants.HTTP_UNAUTHORIZED;
import static org.wso2.km.ext.isam.Constants.JSON_CONTENT;

public class IsamKm extends AMDefaultKeyManagerImpl {

    private static final Log log = LogFactory.getLog(IsamKm.class);
    private String clientId;
    private String clientSecret;
    private int tokenLength;
    private String accessToken = null;

    private String tokenEndpoint;
    private String introspectionEndpoint;
    private String clientRegisterEndpoint;
    private String schema = null;

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
            if (StringUtils.isNotEmpty(configuration.getParameter(Constants.CONFIG_TOKEN_LENGTH))) {
                tokenLength = Integer.parseInt(configuration.getParameter(Constants.CONFIG_TOKEN_LENGTH));
            } else {
                throw new APIManagementException(
                        "[ISAM KM] Unable to find the <TokenLength> property under <IsamKm> configuration.");
            }
            if (StringUtils.isNotEmpty(configuration.getParameter("schema"))) {
                schema = configuration.getParameter("schema");
            }
        }
        super.loadConfiguration(configuration);
    }

    @Override
    public OAuthApplicationInfo createApplication(OAuthAppRequest oauthAppRequest) throws APIManagementException {
        OAuthApplicationInfo info = oauthAppRequest.getOAuthApplicationInfo();
        Application application = getApplication(info);
        if (isISAM(application)) {
            JSONObject response = createApplication(application).getResponse();
            OAuthApplicationInfo applicationInfo = new OAuthApplicationInfo();
            try {
                applicationInfo.setClientId(response.getString("client_id"));
                applicationInfo.setClientSecret(response.getString("client_secret"));
                applicationInfo.setCallBackURL(response.getJSONArray("redirect_uris").getString(0));
                return applicationInfo;
            } catch (JSONException e) {
                throw new APIManagementException("Unable to retrieve information from the client creation response.",
                                                 e);
            }
        } else {
            return super.createApplication(oauthAppRequest);
        }
    }

    private boolean isISAM(Application application) {
        Map<String, String> attributes = application.getApplicationAttributes();
        String idp = attributes.get("IDP");
        return idp.equalsIgnoreCase("isam");
    }

    @Override
    public void deleteApplication(String consumerKey) throws APIManagementException {
        OAuthApplicationInfo info = retrieveApplication(consumerKey);
        Application application = getApplication(info);
        if (isISAM(application)) {
            deleteApplication(application, info.getClientId());
        } else {
            super.deleteApplication(consumerKey);
        }
    }

    @Override
    public AccessTokenInfo getTokenMetaData(String accessToken) throws APIManagementException {
        int length = accessToken.length();
        if (length == tokenLength) {
            try {
                OAuthResponse res = sendIntrospection(accessToken);
                if (res.getStatusCode() == HTTP_OK) {
                    JSONObject response = res.getResponse();
                    AccessTokenInfo tokenInfo = new AccessTokenInfo();
                    boolean isActive = response.getBoolean(Constants.ACTIVE);
                    tokenInfo.setTokenValid(isActive);
                    if (isActive) {
                        tokenInfo.setValidityPeriod(
                                response.getLong(Constants.EXPIRY) - response.getLong(Constants.TOKEN_ISSUED_TIME));
                        tokenInfo.setScope(response.getString(Constants.SCOPE).split(" "));
                        tokenInfo.setConsumerKey(response.getString(CLIENT_ID));
                        tokenInfo.setIssuedTime(response.getLong(Constants.TOKEN_ISSUED_TIME));
                        tokenInfo.setEndUserName(response.getString(Constants.USERNAME));
//                    tokenInfo.addParameter("param1", "para1value");
                    }
                    return tokenInfo;
                } else {
                    throw new APIManagementException(
                            "ISAM introspection endpoint respond with " + res.getStatusCode() + ", Error: " +
                                    (res.getResponse().has(ERROR_DESCRIPTION) ?
                                            res.getResponse().getString(ERROR_DESCRIPTION) : ""));
                }
            } catch (JSONException e) {
                throw new APIManagementException(e);
            }
        } else {
            return super.getTokenMetaData(accessToken);
        }
    }

    private Application getApplication(OAuthApplicationInfo oAuthApplicationInfo)
            throws APIManagementException {
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
            HttpEntity entity = response.getEntity();
            JSONObject responseJson = new JSONObject(EntityUtils.toString(entity, UTF_8));
            EntityUtils.consumeQuietly(entity);
            return new OAuthResponse(statusCode, responseJson);
        } catch (JSONException e) {
            throw new APIManagementException("Malformed JSON response from " + method.getURI().getPath(), e);
        } catch (Exception e) {
            throw new APIManagementException("Could not retrieve response from " + method.getURI().getPath(), e);
        }
    }

    private OAuthResponse createApplication(Application application) throws APIManagementException {
        try {
            if (accessToken == null) {
                accessToken = getAccessToken();
            }
            HttpPost post = getCreateApplicationPostMethod(application);
            OAuthResponse res = executeHttpMethod(post);
            if (res.getStatusCode() == HTTP_UNAUTHORIZED || res.getStatusCode() == HTTP_FORBIDDEN) {
                accessToken = getAccessToken();
                post.releaseConnection();
                post.setHeader(AUTH_HEADER, getAuthorizationHeaderForAccessToken());
                res = executeHttpMethod(post);
            }
            if (res.getStatusCode() != HTTP_OK) {
                throw new APIManagementException(
                        "Could not create application successfully in the ISAM. ISAM respond with " +
                                res.getStatusCode() + ", Error: " + (res.getResponse().has(ERROR_DESCRIPTION) ?
                                res.getResponse().getString(ERROR_DESCRIPTION) : ""));
            }
            return res;
        } catch (JSONException e) {
            throw new APIManagementException("Could not create the application.", e);
        }
    }

    private void deleteApplication(Application application, String clientId) throws APIManagementException {
        try {
            if (accessToken == null) {
                accessToken = getAccessToken();
            }
            HttpDelete delete = getDeleteApplicationDeleteMethod(application, clientId);
            OAuthResponse response = executeHttpMethod(delete);
            if (response.getStatusCode() == HTTP_UNAUTHORIZED || response.getStatusCode() == HTTP_FORBIDDEN) {
                accessToken = getAccessToken();
                delete.releaseConnection();
                delete.setHeader(AUTH_HEADER, getAuthorizationHeaderForAccessToken());
                response = executeHttpMethod(delete);
            }
            if (response.getStatusCode() != HTTP_OK || response.getStatusCode() != Constants.HTTP_NO_CONTENT) {
                throw new APIManagementException(
                        "Could not delete the application from ISAM. ISAM respond with  " + response.getStatusCode() +
                                ", Error: " + (response.getResponse().has(ERROR_DESCRIPTION) ?
                                response.getResponse().getString(ERROR_DESCRIPTION) : ""));
            }
        } catch (JSONException e) {
            throw new APIManagementException("Could not delete the application.", e);
        }
    }

    private OAuthResponse sendIntrospection(String token) throws APIManagementException {
        HttpPost post = getIntrospectionPostMethod(token);
        return executeHttpMethod(post);
    }

    private String getAccessToken() throws APIManagementException {
        try {
            HttpPost post = getAccessTokenPostMethod();
            OAuthResponse res = executeHttpMethod(post);
            if (res.getStatusCode() == 200) {
                return res.getResponse().getString(Constants.ACCESS_TOKEN);
            } else {
                throw new APIManagementException(
                        "Could not retrieve access token for client: " + clientId + ". Endpoint res with " +
                                res.getStatusCode() + ", Error: " + (res.getResponse().has(ERROR_DESCRIPTION) ?
                                res.getResponse().getString(ERROR_DESCRIPTION) : ""));
            }
        } catch (JSONException e) {
            throw new APIManagementException("access_token entry not available in the response.", e);
        }
    }

    private HttpPost getCreateApplicationPostMethod(Application application)
            throws JSONException {
        String url = clientRegisterEndpoint + "/" + (schema != null ? schema : application.getName());
        HttpPost post = new HttpPost(url);
        post.addHeader(AUTH_HEADER, getAuthorizationHeaderForAccessToken());
        post.setEntity(getCreateApplicationPayloadEntity(application));
        return post;
    }

    private StringEntity getCreateApplicationPayloadEntity(Application application) throws JSONException {
        JSONObject jsonPayload = new JSONObject();
        JSONArray redirectsUris = new JSONArray();
        redirectsUris.put(application.getCallbackUrl());
        for (Map.Entry<String, String> entry : application.getApplicationAttributes().entrySet()) {
            jsonPayload.put(entry.getKey(), entry.getValue());
        }
        jsonPayload.put("redirect_uris", redirectsUris);
        StringEntity entity = new StringEntity(jsonPayload.toString(), UTF_8);
        entity.setContentType(JSON_CONTENT);
        return entity;
    }

    private HttpDelete getDeleteApplicationDeleteMethod(Application application, String clientId) {
        String url = clientRegisterEndpoint + "/" +
                (schema != null ? schema : application.getName()) + "?client_id=" + clientId;
        HttpDelete delete = new HttpDelete(url);
        delete.addHeader(AUTH_HEADER, getAuthorizationHeaderForAccessToken());
        return delete;
    }

    private HttpPost getAccessTokenPostMethod() {
        HttpPost post = new HttpPost(tokenEndpoint);
        post.setEntity(getAccessTokenPayloadEntity());
        return post;
    }

    private UrlEncodedFormEntity getAccessTokenPayloadEntity() {
        List<BasicNameValuePair> parametersBody = new ArrayList<>(7);
        parametersBody.add(new BasicNameValuePair(Constants.GRANT_TYPE, Constants.GRANT_CLIENT_CREDENTIALS));
        parametersBody.add(new BasicNameValuePair(CLIENT_ID, clientId));
        parametersBody.add(new BasicNameValuePair(CLIENT_SECRET, clientSecret));
        parametersBody.add(new BasicNameValuePair(Constants.TOKEN_TYPE_HINT, Constants.ACCESS_TOKEN));
        UrlEncodedFormEntity entity = new UrlEncodedFormEntity(parametersBody, UTF_8);
        entity.setContentType(JSON_CONTENT);
        return entity;
    }

    private HttpPost getIntrospectionPostMethod(String token) {
        HttpPost post = new HttpPost(introspectionEndpoint);
        post.setEntity(getIntrospectionPayloadEntity(token));
        return post;
    }

    private UrlEncodedFormEntity getIntrospectionPayloadEntity(String token) {
        List<BasicNameValuePair> parametersBody = new ArrayList<>(5);
        parametersBody.add(new BasicNameValuePair(CLIENT_ID, clientId));
        parametersBody.add(new BasicNameValuePair(CLIENT_SECRET, clientSecret));
        parametersBody.add(new BasicNameValuePair(Constants.TOKEN, token));
        UrlEncodedFormEntity entity = new UrlEncodedFormEntity(parametersBody, UTF_8);
        entity.setContentType(JSON_CONTENT);
        return entity;
    }

    private String getAuthorizationHeaderForAccessToken() {
        return Constants.BEARER + " " + accessToken;
    }
}
