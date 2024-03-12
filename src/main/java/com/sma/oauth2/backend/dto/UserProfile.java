package com.sma.oauth2.backend.dto;

public record UserProfile(String givenName,
                          String familyName,
                          String address,
                          String email,
                          String id) {
}
