package io.jay.springsecurityjwt.authentication.rest;

import io.jay.springsecurityjwt.authentication.JwtTokenProvider;
import io.jay.springsecurityjwt.authentication.User;
import io.jay.springsecurityjwt.authentication.UserRepository;
import io.jay.springsecurityjwt.authentication.UserRole;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

@RestController
public class UserController {

    private final PasswordEncoder passwordEncoder;
    private final JwtTokenProvider jwtTokenProvider;
    private final UserRepository userRepository;

    public UserController(PasswordEncoder passwordEncoder, JwtTokenProvider jwtTokenProvider, UserRepository userRepository) {
        this.passwordEncoder = passwordEncoder;
        this.jwtTokenProvider = jwtTokenProvider;
        this.userRepository = userRepository;
    }

    @PostMapping("/sign-up")
    public Long signup(@RequestBody Map<String, String> user) {

        List<UserRole> roles = new ArrayList<>();
        roles.add(UserRole.ROLE_USER);
        roles.add(UserRole.ROLE_ADMIN);

        User newUser = User.builder()
                .email(user.get("email"))
                .password(passwordEncoder.encode(user.get("password")))
                .roles(roles)
                .build();
        return userRepository.save(newUser).getId();
    }

    @PostMapping("/login")
    public TokenResponse login(@RequestBody Map<String, String> user) {
        User member = userRepository.findByEmail(user.get("email"))
                .orElseThrow(() -> new IllegalArgumentException("No such user for this email"));
        if (!passwordEncoder.matches(user.get("password"), member.getPassword())) {
            throw new IllegalArgumentException("Wrong password");
        }
        return TokenResponse.builder()
                .accessToken(jwtTokenProvider.createAccessToken(member))
                .refreshToken(jwtTokenProvider.createRefreshToken(member))
                .build();
    }

    @GetMapping("/users/hello")
    public String hello() {
        return "Hello user from /users/hello";
    }

    @GetMapping("/admin/{id}")
    public User getUser(@PathVariable Long id) {
        User user = userRepository.findById(id).get();
        return user;
    }
}
