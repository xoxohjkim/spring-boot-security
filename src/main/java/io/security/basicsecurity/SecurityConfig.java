package io.security.basicsecurity;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {
	
	@Autowired
	UserDetailsService userDetailService;
	
	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
	      //test - memory를 이용한 사용자추가
	    auth.inMemoryAuthentication().withUser("user").password("{noop}1234").roles("USER"); //{noop} => passwordEncoder 사용하지 않고 평문으로 비밀번호 사용
	    auth.inMemoryAuthentication().withUser("sys").password("{noop}1111").roles("SYS"); // 여기서는 sys는 sys만 가지고 있음. sys는 user 권한을 가지고 있지 않다. ↓↓↓
	    auth.inMemoryAuthentication().withUser("admin").password("{noop}1111").roles("ADMIN", "SYS", "USER"); 					// <- 이런식으로 적을 수 있음
	}
	
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		// - test
		
		http
			.authorizeRequests()
				.antMatchers("/user").hasRole("USER")	
				.antMatchers("/admin/pay").hasRole("ADMIN")								
				.antMatchers("/admin/**").access("hasRole('ADMIN') or hasRole('SYS')") // 만약 /admin/pay를 하위에 적을 경우 sys권한도 admin/pay에 접근할 수 있게됨 => 그래서 구체적인 범위를 먼저 적는다.
				.anyRequest().authenticated();
		
		http.formLogin();
		
		
		// * handler에서 로그인,로그아웃 시 구현하고 싶은 로직 구현
		
		// * 인가  - 어떤 요청이라도 인증을 받겠다는 정책
		//	       루트경로로 접근 시 로그인

			
		/*
		remember me 인증
			1. 세션 만료되고 웹 브라우저 종료 후에도 app이 사용자를 기억하는 기능
			2. remember-me 쿠기에 대한 http요청을 확인한 후 토큰 기반 인증을 사용해 유효성을 검사하고 토큰 검증 시 사용자는 로그인됨
			3. 사용자 라이프 사이클
				- 인증성공(remember-me쿠키설정)
				- 인증실패(쿠키 존재 시 쿠키 무효화)
				- 로그아웃(쿠키 존재 시 쿠키 무효화)
		
		
		http
			.rememberMe()
				.rememberMeParameter("remember") 		//기본 파라미터명은 remember-me
				.tokenValiditySeconds(3600)				//default 14일, 3600-1시간
				//.alwaysRemember(false) 					//리멤버미 기능이 활성화되지 않아도 항상 실행  - 원래 false임
				.authenticationSuccessHandler(new AuthenticationSuccessHandler() {
					
					@Override
					public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
							Authentication authentication) throws IOException, ServletException {
						response.sendRedirect("/");
						
					}
				})
				.userDetailsService(userDetailService);
		*/
		
		// * 인증 - form login으로 인증
		/*
		http
			.formLogin()
				
				//.loginPage("/login")										//사용자 정의 로그인페이지
				.defaultSuccessUrl("/")										//로그인 성공 후 이동 page
				.failureUrl("/login")										//로그인 실패 후 이동 page
				.usernameParameter("userId")								//아이디 파라미터명 설정
				.passwordParameter("passwd")								//패스워드 파라미터명 설정
				.loginProcessingUrl("/login_proc")							//로그인 form action url
				.successHandler(new AuthenticationSuccessHandler() { 		//로그인 성공 후 핸들러
					
					@Override
					public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
							Authentication authentication) throws IOException, ServletException {
						System.out.println("성공 - authentication : " + authentication.getName());
						response.sendRedirect("/");
						
					}
				})	
				.failureHandler(new AuthenticationFailureHandler() {		//로그인실패 후 핸들러
					
					@Override
					public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
							AuthenticationException exception) throws IOException, ServletException {
						System.out.println("실패 - exception: " + exception.getMessage());
						response.sendRedirect("/login");
						
					}
				})
				.permitAll();		
												//로그인 페이지 permitAll
		*/
		
		// * 로그아웃 - 기본적으로 post 이나 get도 가능
		/*
		http
			.logout()
				.logoutUrl("/logout")
				.logoutSuccessUrl("/")
				.addLogoutHandler(new LogoutHandler() {
					
					@Override
					public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
						HttpSession session = request.getSession();
						session.invalidate();
						
					}
				})
				.logoutSuccessHandler(new LogoutSuccessHandler() {
					
					@Override
					public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication)
							throws IOException, ServletException {
						response.sendRedirect("/login");
						
					}
				})
				.deleteCookies("remember-me");		//로그인 시 remember-me이름으로 쿠키발급됨 - 삭제하기
		
		*/
		
		
		/*
		 * < SessionManagementFilter >
		 */
		
		// * 동시 세션 제어 
		/*
		http
			.sessionManagement()
				.maximumSessions(1) 					// 최대 허용가능 세션 수, -1이면 무제한
				.maxSessionsPreventsLogin(false);		// 동시 로그인 차단함. true일 시 로그인도 불가능. false일 시 먼저 로그인한 계정 session 만료뜸. default: false(기존 세션 만료)
//				.invalidSessionUrl("/invalid")			// 세션이 유효하지 않을 때 이동할 페이지
//				.expiredUrl("/expired");				// 세션이 만료된 경우 이동할 페이지
				
		
		// * 세션고정보호 - 공격자 세션쿠키로 로그인 시도하더라도 로그인 인증시 새로운 세션id 발급하여 보호
		http
			.sessionManagement()
			.sessionFixation()
			.changeSessionId();	// 기본값(servlet3.1 이상) - 새로운 세션 id 								
			// none - 보호 x
			// migrateSession - 기본값(servlet3.1 이하) - 새로운 세션 id. 속성값 유지
			// newSession - 새로운 세션, 새로운 세션 id. 속성값 유지 X
		
		// * 세션 정책
		http
			.sessionManagement()
			.sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED);		// 스프링시큐리티가 필요 시 생성(기본값)
			
			//SessionCreationPolicy.ALWAYS		: 스프링시큐리티가 항상 세션 생성
			//SessionCreationPolicy.IF_REQUERED	: 스프링시큐리티가 필요 시 세션 생성(기본값)
			//SessionCreationPolicy.NEVER		: 스프링 시큐리티가 생성하지 않지만 이미 존재하면 사용
			//SessionCreationPolicy.STATELESS	: 스프링 시큐리티가 생성하지 않고 존재해도 사용하지 않음
				// => stateless 사용 : session cookie가 아니고 session을 사용하지 않을 때.
				// 	  ex) json web token(JWT)사용 시. 토큰에 사용자정보 등 저장하고 세션없이 인증받는 방식
		
		
		/*
		 *  < ConcurrentSessionFilter > 
		 *   1. 동시적 세션 제어를 위해 [sessionManagementFilter]와 연계
		 *   2. 매 요청마다 현재 사용자의 세션 만료 여부 체크 -> sessionManagementFilter안에서 만료 여부 확인
		 *   3. 세션의 만료되었을 경우 즉시 만료 처리
		 *   session.idExpired() == true => 로그아웃 처리
		 *   
		 */

		
		/*
		 * 인가API - 권한 설정
		 */
		
		//
		/*
		http
			.antMatcher("/shop/**")		// 특정한 url정보를 받아서 처리하고자 할때 경로 적기, 안적으면 모든 것 처리
			.authorizeRequests()
				.antMatchers("/shop/login", "/shop/users/**").permitAll()					//이 경로에 대한 요청은 정보가 일치되면 허용한다
				.antMatchers("/shop/mypage").hasRole("USER")								//이 요청은 USER role이어야한다
				.antMatchers("/shop/admin/pay").access("hasRole('ADMIN')")
				.antMatchers("/shop/admin/**").access("hasRole('ADMIN') or hasRole('SYS')")
				.anyRequest().authenticated();													//인증받아야 어떠한 요청도 허용한다
		*/
		// 주의사항  - 설정 시 구체적인 경로가 먼저 나오고 그것보다 큰 범위의 경로가 뒤에 오도록 해야한다
		//         ex) pay 다음에 ** 이므로  반대일 시 , sys사용자도 /pay 접근하게 됨 
	
	}

}
