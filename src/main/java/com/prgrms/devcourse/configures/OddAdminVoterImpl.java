package com.prgrms.devcourse.configures;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Component;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.apache.commons.lang3.math.NumberUtils.toInt;

@Component
public class OddAdminVoterImpl {

    static final Pattern PATTERN = Pattern.compile("[0-9]+$");

    public boolean isOddAdmin(Authentication authentication){
        User user = (User) authentication.getPrincipal();
        String name = user.getUsername();
        Matcher matcher = PATTERN.matcher(name); // 끝에 숫자가 있다면

        // 숫자로 반혼하기
        if(matcher.find()) {
            int number = toInt(matcher.group(),0);
            return number % 2 ==1;
        }
        return false;
    }
}
