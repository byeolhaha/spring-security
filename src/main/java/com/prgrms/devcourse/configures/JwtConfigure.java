package com.prgrms.devcourse.configures;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Component
@ConfigurationProperties(prefix ="jwt" )
public class JwtConfigure {

    private String header;
    private String issuer;
    private String clientSecret;
    private int expirySecond;

    public String getHeader() {
        return header;
    }

    public String getIssuer() {
        return issuer;
    }

    public String getClientSecret() {
        return clientSecret;
    }

    public int getExpirySecond() {
        return expirySecond;
    }

    public void setHeader(String header) {
        this.header = header;
    }

    public void setIssuer(String issuer) {
        this.issuer = issuer;
    }

    public void setClientSecret(String clientSecret) {
        this.clientSecret = clientSecret;
    }

    public void setExpirySecond(int expirySecond) {
        this.expirySecond = expirySecond;
    }

    @Override
    public String toString() {
        return "JwtConfigure{" +
                "header='" + header + '\'' +
                ", issuer='" + issuer + '\'' +
                ", clientSecret='" + clientSecret + '\'' +
                ", expirySecond=" + expirySecond +
                '}';
    }
}
