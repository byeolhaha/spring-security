package com.prgrms.devcourse.user;

public class LoginRequest {

    private String principal;

    private String credential;

    protected LoginRequest() { }

    public LoginRequest(String principal, String credential) {
        this.principal = principal;
        this.credential = credential;
    }

    public String getPrincipal() {
        return principal;
    }

    public String getCredential() {
        return credential;
    }

    @Override
    public String toString() {
        return "LoginRequest{" +
                "principal='" + principal + '\'' +
                ", credential='" + credential + '\'' +
                '}';
    }

}
