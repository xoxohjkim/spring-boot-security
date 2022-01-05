package io.security.basicsecurity;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class SecurityContoller {
	
	@GetMapping("/")
	public String index() {
		return "home";
	}
	
	@GetMapping("/loginPage")
	public String login() {
		return "loginPage"; 
			
	}
	
}
