package com.cos.securityex01.config.auth;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.cos.securityex01.model.User;
import com.cos.securityex01.repository.UserRepository;


@Service
public class PrincipalDetailsService implements UserDetailsService{
	@Autowired
	private UserRepository userRepository;

	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		System.out.println("여긴 auth.principalDetailsService.java = ");
		User user = userRepository.findByUsername(username);
		System.out.println("여긴 auth.principalDetailsService.java 후 = "+user);
		if(user ==null) {
			return null;
		}
		return new PrincipalDetails(user);
	}


}
