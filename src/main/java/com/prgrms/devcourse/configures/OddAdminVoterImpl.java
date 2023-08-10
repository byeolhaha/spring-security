package com.prgrms.devcourse.configures;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.User;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Configuration
public class OddAdminVoterImpl {

    static final Pattern PATTERN = Pattern.compile("[0-9]+$");

    public boolean isOddAdmin(Authentication authentication){
        User user = (User) authentication.getPrincipal();
        String name = user.getUsername();
        Matcher matcher = PATTERN.matcher(name); // 끝에 숫자가 있다면

        // 숫자로 반혼하기
        if(matcher.find()) {
            int number = Integer.parseInt(matcher.group());
            return number % 2 ==1;
        }
        return false;
    }
}
