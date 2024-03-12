package com.sma.oauth2.backend.controller;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sma.oauth2.backend.dto.UserProfile;
import com.sma.oauth2.backend.utils.CookieUtils;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.configurationprocessor.json.JSONException;
import org.springframework.boot.configurationprocessor.json.JSONObject;
import org.springframework.http.*;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import java.util.Base64;
import java.util.HashMap;

import static com.sma.oauth2.backend.model.Constants.*;


@Slf4j
@RestController
@RequestMapping("/bff") // базовый URI
@RequiredArgsConstructor
public class BFFController {
    private final CookieUtils cookieUtils;
    private final ObjectMapper mapper;
    private static final RestTemplate restTemplate = new RestTemplate();

    @Value("${keycloak.secret}")
    private String clientSecret;
    @Value("${resourceserver.url}")
    private String resourceServerURL;
    @Value("${keycloak.url}")
    private String keyCloakURI;
    @Value("${client.url}")
    private String clientURL;
    @Value("${keycloak.clientid}")
    private String clientId;
    @Value("${keycloak.granttype.code}")
    private String grantTypeCode;
    @Value("${keycloak.granttype.refresh}")
    private String grantTypeRefresh;
    private JSONObject payload;
    private String accessToken;
    private String idToken;
    private String refreshToken;
    private int accessTokenDuration;
    private int refreshTokenDuration;


    @GetMapping("/data")
    public ResponseEntity<String> data(@CookieValue("AT") String accessToken) {
        var headers = new HttpHeaders();
        headers.setBearerAuth(accessToken);
        var request = new HttpEntity<>(headers);
        return restTemplate.exchange(resourceServerURL + "/user/data", HttpMethod.GET, request, String.class);
    }

    @PostMapping("/token")
    public ResponseEntity<String> token(@RequestBody String code) {
        var request = new HttpEntity<>(getMapFormByCode(code), getHeaders());
        var response = restTemplate
                .exchange(keyCloakURI + "/token", HttpMethod.POST, request, String.class);
        try {
            parseResponse(response); // получить все нужные поля ответа KC
            var responseHeaders = createCookies();
            return ResponseEntity.ok().headers(responseHeaders).build();
        } catch (JsonProcessingException | JSONException e) {
            log.error("An error occurred while retrieving the token: {}", e.getMessage());
        }
        return ResponseEntity.badRequest().build();
    }

    @GetMapping("/exchange")
    public ResponseEntity<String> exchangeRefreshToken(@CookieValue("RT") String oldRefreshToken) {
        var request = new HttpEntity<>(getMapFormByRT(oldRefreshToken), getHeaders());
        var response = restTemplate
                .exchange(keyCloakURI + "/token", HttpMethod.POST, request, String.class);
        try {
            parseResponse(response);
            var responseHeaders = createCookies();
            return ResponseEntity.ok().headers(responseHeaders).build();
        } catch (JsonProcessingException | JSONException e) {
            log.error("An error occurred while retrieving the new Access token: {}", e.getMessage());
        }
        return ResponseEntity.badRequest().build();
    }

    @GetMapping("/profile")
    public ResponseEntity<UserProfile> profile() {
        var userId = getPayloadValue("sid");
        UserProfile userProfile = new UserProfile(
                getPayloadValue("given_name"),
                getPayloadValue("family_name"),
                getPayloadValue("address"),
                getPayloadValue("email"),
                userId
        );

        return ResponseEntity.ok(userProfile);
    }

    @GetMapping("/logout")
    public ResponseEntity<String> logout(@CookieValue("IT") String idToken) {
        var urlTemplate = UriComponentsBuilder.fromHttpUrl(keyCloakURI + "/logout")
                .queryParam(POST_LOGOUT_REDIRECT_URI, "{post_logout_redirect_uri}")
                .queryParam(ID_TOKEN_HINT, "{id_token_hint}")
                .queryParam(CLIENT_ID, "{client_id}")
                .encode()
                .toUriString();
        var params = new HashMap<String, String>();
        params.put(POST_LOGOUT_REDIRECT_URI, clientURL);
        params.put(ID_TOKEN_HINT, idToken);
        params.put(CLIENT_ID, clientId);
        var response = restTemplate
                .getForEntity(urlTemplate, String.class, params);
        if (response.getStatusCode() == HttpStatus.OK) {
            HttpHeaders responseHeaders = clearCookies();
            return ResponseEntity.ok().headers(responseHeaders).build();
        }
        return ResponseEntity.badRequest().build();
    }

    private MultiValueMap<String, String> getMapFormByCode(String code) {
        MultiValueMap<String, String> mapForm = new LinkedMultiValueMap<>();
        mapForm.add(GRANT_TYPE, grantTypeCode);
        mapForm.add(CLIENT_ID, clientId);
        mapForm.add(CLIENT_SECRET, clientSecret);
        mapForm.add(CODE, code);
        mapForm.add(REDIRECT_URI, clientURL);
        return mapForm;
    }

    private MultiValueMap<String, String> getMapFormByRT(String oldRefreshToken) {
        MultiValueMap<String, String> mapForm = new LinkedMultiValueMap<>();
        mapForm.add(GRANT_TYPE, grantTypeRefresh);
        mapForm.add(CLIENT_ID, clientId);
        mapForm.add(CLIENT_SECRET, clientSecret);
        mapForm.add(REFRESH_TOKEN, oldRefreshToken);
        return mapForm;
    }

    private static HttpHeaders getHeaders() {
        var headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        return headers;
    }

    private HttpHeaders createCookies() {
        var accessTokenCookie = cookieUtils.getCookie(ACCESS_TOKEN_COOKIE_KEY, accessToken, accessTokenDuration);
        var refreshTokenCookie = cookieUtils.getCookie(REFRESH_TOKEN_COOKIE_KEY, refreshToken, refreshTokenDuration);
        var idTokenCookie = cookieUtils.getCookie(ID_TOKEN_COOKIE_KEY, idToken, accessTokenDuration); // задаем такой же срок, что и AT

        var responseHeaders = new HttpHeaders();
        responseHeaders.add(HttpHeaders.SET_COOKIE, accessTokenCookie.toString());
        responseHeaders.add(HttpHeaders.SET_COOKIE, refreshTokenCookie.toString());
        responseHeaders.add(HttpHeaders.SET_COOKIE, idTokenCookie.toString());

        return responseHeaders;
    }

    private HttpHeaders clearCookies() {
        var accessTokenCookie = cookieUtils.deleteCookie(ACCESS_TOKEN_COOKIE_KEY);
        var refreshTokenCookie = cookieUtils.deleteCookie(REFRESH_TOKEN_COOKIE_KEY);
        var idTokenCookie = cookieUtils.deleteCookie(ID_TOKEN_COOKIE_KEY);

        HttpHeaders responseHeaders = new HttpHeaders();
        responseHeaders.add(HttpHeaders.SET_COOKIE, accessTokenCookie.toString());
        responseHeaders.add(HttpHeaders.SET_COOKIE, refreshTokenCookie.toString());
        responseHeaders.add(HttpHeaders.SET_COOKIE, idTokenCookie.toString());
        return responseHeaders;
    }

    private String getPayloadValue(String claim) {
        try {
            return payload.getString(claim);
        } catch (JSONException e) {
            throw new RuntimeException(e);
        }
    }

    private void parseResponse(ResponseEntity<String> response) throws JsonProcessingException, JSONException {
        var root = mapper.readTree(response.getBody());

        accessToken = root.get("access_token").asText();
        idToken = root.get("id_token").asText();
        refreshToken = root.get("refresh_token").asText();

        accessTokenDuration = root.get("expires_in").asInt();
        refreshTokenDuration = root.get("refresh_expires_in").asInt();

        var payloadPart = idToken.split("\\.")[1]; // берем значение раздела payload в формате Base64
        var payloadStr = new String(Base64.getUrlDecoder().decode(payloadPart)); // декодируем из Base64 в обычный текст JSON
        payload = new JSONObject(payloadStr); // формируем удобный формат JSON - из него теперь можно получать любе поля
    }


}

