package com.prgrms.devcourse.configures;

import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.core.Authentication;

import java.util.Collection;

public class OddAdminVoter implements AccessDecisionVoter {

    OddAdminVoterImpl oddAdminVoter = new OddAdminVoterImpl();

    @Override
    public boolean supports(ConfigAttribute attribute) {
        return true;
    }

    @Override
    public int vote(Authentication authentication, Object object, Collection collection) {
        boolean isOddAdmin = oddAdminVoter.isOddAdmin(authentication);

        if (isOddAdmin) {
            return ACCESS_GRANTED;  // Grant access to odd admin users
        } else {
            return ACCESS_DENIED;   // Deny access to other users
        }
    }

    @Override
    public boolean supports(Class clazz) {
        return true;
    }
}
