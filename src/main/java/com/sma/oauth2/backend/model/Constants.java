package com.sma.oauth2.backend.model;

import lombok.AccessLevel;
import lombok.NoArgsConstructor;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
public class Constants {
    public static final String ID_TOKEN_COOKIE_KEY = "IT";
    public static final String REFRESH_TOKEN_COOKIE_KEY = "RT";
    public static final String ACCESS_TOKEN_COOKIE_KEY = "AT";
    public static final String ID_TOKEN = "id_token";
    public static final String ACCESS_TOKEN = "access_token";
    public static final String REFRESH_TOKEN = "refresh_token";
    public static final String EXPIRES_IN = "expires_in";
    public static final String REFRESH_EXPIRES_IN = "refresh_expires_in";
    public static final String CLIENT_ID = "client_id";
    public static final String CLIENT_SECRET = "client_secret";
    public static final String GRANT_TYPE = "grant_type";
    public static final String CODE = "code";
    public static final String REDIRECT_URI = "redirect_uri";
    public static final String ID_TOKEN_HINT = "id_token_hint";
    public static final String POST_LOGOUT_REDIRECT_URI = "post_logout_redirect_uri";

}
