package com.prgrms.devcourse.configures;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.util.matcher.RequestMatcher;

import java.util.Collection;

public class OddAdminVoter implements AccessDecisionVoter<FilterInvocation> {


    private final RequestMatcher requestMatcher;
    private final OddAdminVoterImpl oddAdminVoter;

    public OddAdminVoter(RequestMatcher requestMatcher, OddAdminVoterImpl oddAdminVoter) {
        this.requestMatcher = requestMatcher;
        this.oddAdminVoter = oddAdminVoter;
    }

    @Override
    public boolean supports(ConfigAttribute attribute) {
        return true;
    }

    @Override
    public int vote(Authentication authentication, FilterInvocation fi, Collection<ConfigAttribute> attributes) {
        HttpServletRequest request = fi.getRequest();
        if (!requiresAuthorization(request)) {
            return ACCESS_GRANTED;
        }
        boolean isOddAdmin = oddAdminVoter.isOddAdmin(authentication);

        if (isOddAdmin) {
            return ACCESS_GRANTED;  // Grant access to odd admin users
        }
        return ACCESS_DENIED;   // Deny access to other users

    }

    private boolean requiresAuthorization(HttpServletRequest httpServletRequest) {
        return requestMatcher.matches(httpServletRequest);
    }


    @Override
    public boolean supports(Class clazz) {
        return FilterInvocation.class.isAssignableFrom(clazz);
    }
}
