package com.prgrms.devcourse.configures;


import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.AccessDecisionManager;
import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.expression.SecurityExpressionHandler;
import org.springframework.security.access.vote.UnanimousBased;
import org.springframework.security.authentication.AuthenticationTrustResolverImpl;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.access.expression.WebExpressionVoter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import java.util.ArrayList;
import java.util.List;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
public class WebSecurityConfigure {

    private final Logger log = LoggerFactory.getLogger(getClass());
    private final OddAdminVoterImpl oddAdminVoter;

    public WebSecurityConfigure(OddAdminVoterImpl oddAdminVoter) {
        this.oddAdminVoter = oddAdminVoter;
    }

    // public WebSecurityConfigure(OddAdminVoterImpl oddAdminVoter) {
  //     SecurityContextHolder.setStrategyName(SecurityContextHolder.MODE_INHERITABLETHREADLOCAL);
  //     this.oddAdminVoter = oddAdminVoter;
  // }


    //스프링 시큐리티 필터 채인을 태우지 않겠다는 의미
    // 불필요한 서버 자원 낭비를 방지
    @Bean
    public WebSecurityCustomizer webSecurityCustomizer() {
        return (web) -> web.ignoring()
                .requestMatchers("assects/**");
    }

    public SecurityExpressionHandler<FilterInvocation> securityExpressionHandler() {
        return new CustomWebSecurityExpressionHandler(
                new AuthenticationTrustResolverImpl(),
                "ROLE_"
        );
    }

    @Bean
    public AccessDecisionManager accessDecisionManager() {
        List<AccessDecisionVoter<?>> voters = new ArrayList<>();
        voters.add(new WebExpressionVoter());
        voters.add(new OddAdminVoter(new AntPathRequestMatcher("/admin"), oddAdminVoter));
        return new UnanimousBased(voters);
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .rememberMe(r -> r.rememberMeParameter("remember-me").tokenValiditySeconds(300)
                        .alwaysRemember(false))
                .authorizeRequests(authorize -> authorize
                        .requestMatchers("/me","/asyncHello","/someMethod").hasAnyRole("USER", "ADMIN")
                        .requestMatchers("/admin")
                        .access("isFullyAuthenticated() and hasRole('ADMIN')")
                        .accessDecisionManager(accessDecisionManager())
                        .anyRequest().permitAll()
                )
                .formLogin(login -> login.defaultSuccessUrl("/")
                        .permitAll())
                .logout(logout -> logout
                        .logoutSuccessUrl("/")

                )
                .requiresChannel(
                        channel -> channel.anyRequest().requiresSecure()) // 모든 요청된 채널은 https
                .anonymous(v -> v.principal("thisIsAnonymousUser")
                        .authorities("ROLE_ANONYMOUS", "ROLE_UNKOWN"))
                .exceptionHandling(v -> v.accessDeniedHandler(accessDeniedHandler()))
                .sessionManagement(s->s.sessionFixation().changeSessionId().sessionCreationPolicy(
                        SessionCreationPolicy.IF_REQUIRED).invalidSessionUrl("/").maximumSessions(1).// 최대로 로그인 가능한 세션 개수
                        maxSessionsPreventsLogin(false))// 최대 도달했을 때 로그인을 막을 것인가? 기본값 = false , true 맥시멈 새션에 도달하면 새로운 로그인을 할 수 없다
                .httpBasic(withDefaults());
        return http.build();
    }

    @Bean
    public AccessDeniedHandler accessDeniedHandler() {
        return (request, response, e) ->
        {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            Object principal = authentication != null ? authentication.getPrincipal() : null;
            log.warn("{} is denied", principal, e);
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            response.setContentType("text/plain");
            response.getWriter().write("## ACCESS DENIED! ##");
            response.getWriter().flush();
            response.getWriter().close();
        };


    }

    @Bean
    UserDetailsService userDetailsService() {
        InMemoryUserDetailsManager manager = new InMemoryUserDetailsManager();
        manager.createUser(User.withUsername("user")
                .password("{noop}user123")
                .roles("USER")
                .build());
        manager.createUser(User.withUsername("admin01")
                .password("{noop}admin123")
                .roles("ADMIN")
                .build());
        manager.createUser(User.withUsername("admin02")
                .password("{noop}admin123")
                .roles("ADMIN")
                .build());
        return manager;
    }

}
