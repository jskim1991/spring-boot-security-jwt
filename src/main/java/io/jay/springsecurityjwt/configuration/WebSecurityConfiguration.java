package io.jay.springsecurityjwt.configuration;

import io.jay.springsecurityjwt.authentication.CustomUserDetailService;
import io.jay.springsecurityjwt.authentication.JwtRequestFilter;
import io.jay.springsecurityjwt.authentication.JwtTokenProvider;
import org.springframework.context.annotation.Bean;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@EnableWebSecurity
public class WebSecurityConfiguration extends WebSecurityConfigurerAdapter {

    private final JwtTokenProvider jwtTokenProvider;
    private final CustomUserDetailService customUserDetailService;

    public WebSecurityConfiguration(JwtTokenProvider jwtTokenProvider, CustomUserDetailService customUserDetailService) {
        this.jwtTokenProvider = jwtTokenProvider;
        this.customUserDetailService = customUserDetailService;
    }


    @Bean
    public PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

//    @Override
//    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
//        auth.userDetailsService(customUserDetailService)
//                .passwordEncoder(passwordEncoder());
//    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .httpBasic().disable() // rest api 만 고려하여 기본 설정 해제
                .csrf().disable() // csrf 보안 토큰 disable
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS) // 토큰 기반 인증이라 세션 미사용

                .and()
                .authorizeRequests()
                .antMatchers("/admin/**").hasRole("ADMIN")
                .antMatchers("/users/**").hasRole("USER")
                .anyRequest().permitAll() // 그 외 허용

                .and()
//                .addFilterBefore(new JwtAuthenticationFilter(jwtTokenProvider),
                .addFilterBefore(new JwtRequestFilter(jwtTokenProvider, customUserDetailService),
                        UsernamePasswordAuthenticationFilter.class)
        ;
    }
}
