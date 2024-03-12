package com.sma.oauth2.backend.utils;

import org.apache.tomcat.util.http.SameSiteCookies;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpCookie;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Component;

@Component
public class CookieUtils {

    @Value("${cookie.domain}")
    private String cookieDomain;

    public HttpCookie getCookie(String name, String value, int durationInSeconds) {
        return ResponseCookie
                .from(name, value)
                .maxAge(durationInSeconds)
                .sameSite(SameSiteCookies.STRICT.getValue())
                .httpOnly(true)
                .secure(true)
                .domain(cookieDomain)
                .path("/")
                .build();
    }

    public HttpCookie deleteCookie(String name) {
        return getCookie(name, "", 0);
    }

}
