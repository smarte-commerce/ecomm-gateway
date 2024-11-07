package com.winnguyen1905.gateway.model.response;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.winnguyen1905.gateway.model.AbstractModel;
import com.winnguyen1905.gateway.model.User;

import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@Builder
public class AuthResponse extends AbstractModel {
    @JsonProperty("user")
    private User user;
    private String accessToken;
    @JsonIgnore private String refreshToken;
}