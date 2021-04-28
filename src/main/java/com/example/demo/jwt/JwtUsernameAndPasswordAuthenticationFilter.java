package com.example.demo.jwt;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class JwtUsernameAndPasswordAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
    /*
    this class is for verifing credentials send by client
    Spring security does it but we will overide it
    */


    /*Authenticate to see wether username and password is correct*/
    private final AuthenticationManager authenticationManager;

    @Autowired // we should know how to exactly pass this authenticationManager not the other one
    public JwtUsernameAndPasswordAuthenticationFilter(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
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
            Authentication authenticate = authenticationManager.authenticate(authentication);
            return authenticate;

        }catch (IOException e){
            throw new RuntimeException(e);
        }

        //return super.attemptAuthentication(request, response);
    }
}
