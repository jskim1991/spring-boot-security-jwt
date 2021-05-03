package io.jay.springsecurityjwt.authentication;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Component;

import javax.annotation.PostConstruct;
import javax.servlet.http.HttpServletRequest;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Date;

@Component
public class JwtTokenProvider {

    private final UserDetailsService userDetailsService;
    private String secretKey = "webfirewood";
    private final long accessTokenValidTime = 10 * 60 * 1000L;
    private final long refreshTokenValidTime = 2 * 24 * 60 * 1000L;

    public JwtTokenProvider(UserDetailsService userDetailsService) {
        this.userDetailsService = userDetailsService;
    }

    @PostConstruct
    protected void init() {
        secretKey = Base64.getEncoder().encodeToString(secretKey.getBytes(StandardCharsets.UTF_8));
    }

    public String createAccessToken(User user) {
        return createToken(user, accessTokenValidTime);
    }

    public String createRefreshToken(User user) {
        return createToken(user, refreshTokenValidTime);
    }

    private String createToken(User user, long tokenValidTime) {
        Claims claims = Jwts.claims().setSubject(user.getUsername());
        claims.put("roles", user.getRoles());
        Date now = new Date();
        return Jwts.builder()
                .setClaims(claims)
                .setIssuedAt(now)
                .setExpiration(new Date(now.getTime() + tokenValidTime))
                .signWith(SignatureAlgorithm.HS256, secretKey)
                .compact();
    }

    /**
     * 토큰에서 회원 정보 추출
     * @param token
     * @return
     */
    public String getUsername(String token) {
        return Jwts.parser().setSigningKey(secretKey).parseClaimsJws(token).getBody().getSubject();
    }

    public String resolveToken(HttpServletRequest request) {
        return request.getHeader("Authorization");
    }

    /**
     * 토근 유효성 및 만료일자 확인
     * @param jwtToken
     * @return
     */
    public boolean validateToken(String jwtToken, UserDetails userDetails) {
        try {
            Jws<Claims> claims = Jwts
                    .parser()
                    .setSigningKey(secretKey)
                    .parseClaimsJws(jwtToken);
            return !claims.getBody().getExpiration().before(new Date()) &&
                    getUsername(jwtToken).equals(userDetails.getUsername());
        } catch (Exception e) {
            System.out.println(e);
            return false;
        }
    }
}
