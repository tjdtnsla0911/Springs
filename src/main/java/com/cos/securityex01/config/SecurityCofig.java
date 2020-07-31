package com.cos.securityex01.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import ch.qos.logback.core.pattern.color.BoldCyanCompositeConverter;

@Configuration //Ioc에 빈(Bean)을 등록   빈 = 객체
@EnableWebSecurity //필터 체인 관리 시작
@EnableGlobalMethodSecurity(prePostEnabled = true) //특정 주소 접근시 권한 및 인증을 직접체크한다.
public class SecurityCofig  extends WebSecurityConfigurerAdapter{ //무조껀 다관리할 필요가없으니까 인터페이스가아니라 상속개념임
	@Bean
	public BCryptPasswordEncoder encodePwd() {
		System.out.println("auth.SecurityCofig.java 전");
		return new BCryptPasswordEncoder();
	}
	//한번만뜨면되서 여기둠 암테나도도댐

	@Override //요놈으로인해 http에서 오는요청을 다막아버린다
	protected void configure(HttpSecurity http) throws Exception {
		System.out.println("auth.SecurityConfig.java 의 configure");
			http.csrf().disable(); //disable로 끄고 어차피 javaScript로 할꺼임 이거요샌안검
			http.authorizeRequests()
			.antMatchers("/user/**"
					,"/admin/**")  //여기서 가는경로
			.authenticated()
			.anyRequest()
			.permitAll()
		.and()
			.formLogin()
			.loginPage("/login")
			.loginProcessingUrl("/loginProc")
			.defaultSuccessUrl("/");
			System.out.println("auth.SecurityConfig.java 의 configure는 문제없는듯하오");
			

	}


}
