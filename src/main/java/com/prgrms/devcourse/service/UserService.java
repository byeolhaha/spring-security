package com.prgrms.devcourse.service;

import com.prgrms.devcourse.user.User;
import com.prgrms.devcourse.user.UserRepository;

import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;

@Service
public class UserService {

    private final UserRepository userRepository;

    private final PasswordEncoder passwordEncoder;

    public UserService(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @Transactional(readOnly = true)
    public User login (String username, String credential) {
        User user = userRepository.findByLoginId(username)
                .orElseThrow(()-> new UsernameNotFoundException("Could not fount user for " + username));
        user.checkPassword(passwordEncoder, credential);
        return user;
    }

    @Transactional(readOnly = true)
    public Optional<User> findByLoginId(String loginId) {
        return userRepository.findByLoginId(loginId);
    }

}
