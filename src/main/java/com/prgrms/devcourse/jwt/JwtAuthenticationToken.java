package com.prgrms.devcourse.jwt;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

public class JwtAuthenticationToken extends AbstractAuthenticationToken {

    private final Object principal;

    private String credential;

    // 인증 요청 시
    public JwtAuthenticationToken(String principal, String credential) {
        super(null); // 인증 된 사용자가 아니기에 권한 목록에 null;
        super.setAuthenticated(false);

        this.principal = principal;
        this.credential = credential;
    }

    //인증 완료 시
    JwtAuthenticationToken(Object principal, String credential, Collection<? extends GrantedAuthority> authorities) {
      super(authorities);
      super.setAuthenticated(true);

      this.principal = principal;
      this.credential = credential;
    }

    @Override
    public String getCredentials() {
        return credential;
    }

    @Override
    public Object getPrincipal() {
        return principal;
    }

    @Override
    public void setAuthenticated(boolean authenticated) {
        // 생성자를 통해서만 true가 입력될 수 있도록 예외를 던지기
        if(authenticated) {
           throw new IllegalStateException("Cannot set this token to trusted");
        }
        super.setAuthenticated(authenticated);
    }

    //비밀 번호 지우는
    @Override
    public void eraseCredentials() {
        super.eraseCredentials();
        credential = null;
    }

    @Override
    public String toString() {
        return "JwtAuthenticationToken{" +
                "principal=" + principal +
                ", credential='" + credential + '\'' +
                '}';
    }
}
