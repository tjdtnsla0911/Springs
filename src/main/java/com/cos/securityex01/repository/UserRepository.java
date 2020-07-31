package com.cos.securityex01.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import com.cos.securityex01.model.User;

//JpaRepository를 상속하면 자동 컴포넌트 스캔됨
public interface UserRepository extends JpaRepository<User, Integer>{ //<어느타입에 연결되잇는거니?, 타입>
	//Jpa Naming 전략
	//SELECT * FROM user WHERE username=1?
	User findByUsername(String username);//일케하면 jpa가 개사기라서 직접 만들어줌
//	//SELECT * FROM user WHERE username=1 and password=2?
//	User findByUsernameAndPassword(String username, String apssword);
//
//	@Query(value="select * from user", nativeQuery = true)
//	User find내마음대로();
}
