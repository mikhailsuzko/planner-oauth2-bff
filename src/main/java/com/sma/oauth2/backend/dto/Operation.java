package com.sma.oauth2.backend.dto;

import org.springframework.http.HttpMethod;

public record Operation(
        HttpMethod httpMethod,
        String url,
        Object body) {
}
