package com.example.demo.jwt;

import com.google.common.base.Strings;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import lombok.var;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

public class JwtTokenVerifier extends OncePerRequestFilter {

   /*
   * executed once per request. Each time it will be used
   * */

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        //put breakpoint here
        String authorizationHeader = request.getHeader("Authorization");
        //Strings taken from com.google.common.base
        if (Strings.isNullOrEmpty(authorizationHeader)
                || !authorizationHeader.startsWith("Bearer ")){
            filterChain.doFilter(request,response);
            //header not starting with "Bearer " is rejected
            return;
        }

        String token = authorizationHeader.replace("Bearer", "");
        try {

            String secretKey = "securesecuresecuresecuresecuresecuresecure";
            //allow parse actual token

            //jwt is parsed to jws see documentation
            Jws<Claims> claimsJws = Jwts.parser()
                                        .setSigningKey(Keys.hmacShaKeyFor(secretKey.getBytes()))
                                        .parseClaimsJws(token);

            Claims body = claimsJws.getBody();
            String username = body.getSubject();//linda
            var authorities =  (List<Map<String,String>>) body.get("authorities");

            //mapping to list, each item getting authority so we can map into the authority(Student:write)
            Set<SimpleGrantedAuthority> simpleGrantedAuthorities = authorities.stream()
                    .map(m -> new SimpleGrantedAuthority(m.get("authority")))
                    .collect(Collectors.toSet());

            //needs to be collection that extends granted authority
            Authentication authentication = new UsernamePasswordAuthenticationToken(
                    username,
                    null,
                    simpleGrantedAuthorities  //authorities

            );
            //client assigned the token now authenticated
            SecurityContextHolder.getContext().setAuthentication(authentication);

        }catch (JwtException e){
            throw new IllegalStateException(String.format("Token %s cannot be trusted", token));
        }


        //ask for the next filter in the FilterChain
        filterChain.doFilter(request,response);


    }
}
