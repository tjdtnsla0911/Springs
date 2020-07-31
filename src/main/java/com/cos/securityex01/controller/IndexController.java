package com.cos.securityex01.controller;



import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import com.cos.securityex01.config.auth.PrincipalDetails;
import com.cos.securityex01.model.User;
import com.cos.securityex01.repository.UserRepository;


@Controller
public class IndexController {

	@Autowired
	private UserRepository userRepository;

	@Autowired
	private BCryptPasswordEncoder bCryptPasswordEncoder;





@GetMapping({"/",""})
public @ResponseBody String index() {
	return "인덱스 페이지 입니다";
}
@GetMapping("/user")
public @ResponseBody String user(@AuthenticationPrincipal PrincipalDetails principal) {
	System.out.println("로그인하러왔습니다 . 여긴 contorller.IndexController.java 의 login");
	System.out.println("로그인하러왔습니다 . 여긴 contorller.IndexController.java 의 login의 principal.getUser().getRore() ="+principal.getUser().getRore());
	System.out.println("로그인하러왔습니다 . 여긴 contorller.IndexController.java 의 login의 principal.getAuthorities()= "+principal.getAuthorities());

	System.out.println(principal);
	return "유저 페이지 입니다";
}
@GetMapping("/admin")
public String admiin() {
	return "어드민 페이지 입니다";
}
@GetMapping("/login")
public String login() {
	System.out.println("로그인하러왔습니다 . 여긴 contorller.IndexController.java 의 login");
	return "login";
}
@GetMapping("/join")
public  String join() {
	return "join";
}
@PostMapping("/joinProc")
public String joinProc(User user) {
	System.out.println("회원가입 진행합니다 여긴 Controller.IndexController.java의 joinProc의 시작  user= "+user);
   String rawPassword = user.getPassword();
   String encPassword = bCryptPasswordEncoder.encode(rawPassword);
   user.setPassword(encPassword);
   user.setRore("ROLE_USER");
   userRepository.save(user);
	System.out.println("회원가입 진행합니다 여긴 Controller.IndexController.java의 joinProc의 끝(리턴전)  user= "+user);
	return "redirect:/";
}
}
