package com.springsecurity.jwt.config.auth;

import com.springsecurity.jwt.model.User;
import com.springsecurity.jwt.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class PrincipalDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        System.out.println("PrincipalDetailsService-loadUserByUsername");
        User userEntity = userRepository.findByUsername(username);
        System.out.println("UserEntity:" + userEntity);
        return new PrincipalDetails(userEntity);
    }
}
