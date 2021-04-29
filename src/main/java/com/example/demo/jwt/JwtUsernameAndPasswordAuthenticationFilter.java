package com.example.demo.jwt;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Jwts;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.crypto.SecretKey;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.time.LocalDate;
import java.util.Date;

public class JwtUsernameAndPasswordAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
    /*
    this class is for verifing credentials send by client
    Spring security does it but we will overide it
    */


    /*Authenticate to see wether username and password is correct*/
    private final AuthenticationManager authenticationManager;
    private final JwtConfig jwtConfig;
    private final SecretKey secretKey;

    @Autowired // we should know how to exactly pass this authenticationManager not the other one
    public JwtUsernameAndPasswordAuthenticationFilter(AuthenticationManager authenticationManager,
                                                      JwtConfig jwtConfig,
                                                      SecretKey secretKey) {

        this.authenticationManager = authenticationManager;
        this.jwtConfig = jwtConfig;
        this.secretKey = secretKey;
    }


    @Override
    public Authentication attemptAuthentication(HttpServletRequest request,
                                                HttpServletResponse response) throws AuthenticationException {



        try {

            UsernameAndPasswordAuthenticationRequest authenticationRequest = new ObjectMapper()
                    .readValue(request.getInputStream(), UsernameAndPasswordAuthenticationRequest.class);


            Authentication authentication = new UsernamePasswordAuthenticationToken(
                    authenticationRequest.getUsername(), //principal
                    authenticationRequest.getPassword()  //credential
            );

            //it will ensure whether username exists
            // if it will check password is correct or not
            // kind of validate credentials
            //authenticated will become true if you see in the breakpoint
            Authentication authenticate = authenticationManager.authenticate(authentication);
            //create breakpoint here to check if user can authenticate
            return authenticate;

        }catch (IOException e){
            throw new RuntimeException(e);
        }

        //return super.attemptAuthentication(request, response);
    }


    /*create a JWT token and send it to Client*/
    @Override
    protected void successfulAuthentication(HttpServletRequest request,
                                            HttpServletResponse response,
                                            FilterChain chain,
                                            Authentication authResult) throws IOException, ServletException {


        //create token from io.jsonwebtoken
        // String tempKey = "securesecuresecuresecuresecuresecuresecure";

        String token = Jwts.builder()
                .setSubject(authResult.getName()) //actual subject linda/tom/anna
                .claim("authorities", authResult.getAuthorities()) //body
                .setIssuedAt(new Date())                              //when started token?
                //.setExpiration(java.sql.Date.valueOf(LocalDate.now().plusWeeks(2))) //until when
                .setExpiration(java.sql.Date.valueOf(LocalDate.now().plusDays(jwtConfig.getTokenExpirationAfterDays()))) //until when
                //.signWith(Keys.hmacShaKeyFor(tempKey.getBytes()))
                .signWith(secretKey)
                .compact();


        //send it to client
        //create breakpoint here to check if token is created or not
        response.addHeader(jwtConfig.getAuthorizationHeader(), jwtConfig.getTokenPrefix() + token );



    }
}
