package com.prgrms.devcourse.jwt;

import static org.apache.logging.log4j.util.Strings.isNotEmpty;
import static com.google.common.base.Preconditions.checkArgument;

// 역할 : 인증완료 후 인증된 사용자를 표현하기 위한 객체
public class JwtAuthentication {

    public final String token;
    public final String username;

    public JwtAuthentication(String token, String username) {
        checkArgument(isNotEmpty(token), "token must be provided");
        checkArgument(isNotEmpty(username), "username must be provided");

        this.token = token;
        this.username = username;
    }

    @Override
    public String toString() {
        return "JwtAuthentication{" +
                "token='" + token + '\'' +
                ", username='" + username + '\'' +
                '}';
    }
}
