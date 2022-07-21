package net.dg.jwt.utility;

import io.jsonwebtoken.*;
import net.dg.jwt.constants.LoggingErrors;
import net.dg.jwt.model.UserDetailsImpl;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import java.util.Date;

@Component
public class JwtUtils {
    private static final Logger logger = LoggerFactory.getLogger(JwtUtils.class);

    @Value("${app.jwtSecret}")
    private String jwtSecret;

    @Value("${app.jwtExpirationMs}")
    private int jwtExpirationMs;

    public String generateJwtToken(Authentication authentication) {

        UserDetailsImpl userPrincipal = (UserDetailsImpl) authentication.getPrincipal();

        return Jwts.builder()
                .setSubject((userPrincipal.getUsername()))
                .setIssuedAt(new Date())
                .setExpiration(new Date((new Date()).getTime() + jwtExpirationMs))
                .signWith(SignatureAlgorithm.HS512, jwtSecret)
                .compact();
    }

    public String getUserNameFromJwtToken(String token) {
        return Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(token).getBody().getSubject();
    }

    public boolean validateJwtToken(String authToken) {
        try {
            Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(authToken);
            return true;
        } catch (SignatureException e) {
            logger.error(LoggingErrors.INVALID_JWT_SIGNATURE, e.getMessage());
        } catch (MalformedJwtException e) {
            logger.error(LoggingErrors.INVALID_JWT_TOKEN, e.getMessage());
        } catch (ExpiredJwtException e) {
            logger.error(LoggingErrors.EXPIRED_TOKEN, e.getMessage());
        } catch (UnsupportedJwtException e) {
            logger.error(LoggingErrors.UNSUPPORTED_TOKEN, e.getMessage());
        } catch (IllegalArgumentException e) {
            logger.error(LoggingErrors.EMPTY_TOKEN, e.getMessage());
        }

        return false;
    }
}