package com.phase.security.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
public class JwtService {
    private static final String SECRETE_KEY = "1D01F2DE9827E19C4803597B1F74922FF801BC12847F3A986CDE6D349E70C7C2";
    public String extractUsername(String token){
        return extractClaim(token, Claims::getSubject); // In Subject is where there's Username an Email on our case
    }
    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver){
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

//    Generate the token with Just the user details
    public String generateToken(UserDetails userDetails){
        return generateToken(new HashMap<>(), userDetails);
    }

    public String generateToken(
            Map<String, Object> extractClaims, //this is the one if I want for example to pass Authorities, pass any info that I want to store with in claim
            UserDetails userDetails){
        return Jwts
                .builder()
                .setClaims(extractClaims)
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis())) //when this claim was created helps to calculate the expiration date
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 24)) //Last one day
                .signWith(getSignInKey(), SignatureAlgorithm.HS256)
                .compact(); //Generate and return the token
    }

//    Method to validate token
    public boolean isTokenValid(String token, UserDetails userDetails){ //Check if token belongs to userDetails
        final String username = extractUsername(token);
        return username.equals(userDetails.getUsername()) && isTokenExpired(token); //we want to make sure that username we have in token is same as the username that we have as input
    }

    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    private Claims extractAllClaims(String token){
//      Extract All the claims
       return Jwts
                .parserBuilder()
                .setSigningKey(getSignInKey())
                .build()
                .parseClaimsJws(token)
                .getBody(); //Get All the claims that we have in Token
    }
    private Key getSignInKey() {
        byte[] keyByte = Decoders.BASE64.decode(SECRETE_KEY);
        return Keys.hmacShaKeyFor(keyByte);
    }
}
