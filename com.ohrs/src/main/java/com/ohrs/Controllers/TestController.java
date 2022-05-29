package com.ohrs.Controllers;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.ModelAndView;

@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/api/test")
public class TestController {

	@GetMapping("/all")
	public ModelAndView allAccess() {
		ModelAndView mv = new ModelAndView();
		mv.setViewName("home.html");
		return mv;
	}
	
	@GetMapping("/login")
	public ModelAndView loginPage() {
		ModelAndView mv = new ModelAndView();
		mv.setViewName("login.html");
		return mv;
	}
	
	@GetMapping("/registration")
	public ModelAndView registrationPage() {
		ModelAndView mv = new ModelAndView();
		mv.setViewName("registration.html");
		return mv;
	}
	

	
	@GetMapping("/customer")
	@PreAuthorize("hasRole('CUSTOMER')")
	public String userAccess() {
		return "Customer Content.";
	}

	@GetMapping("/owner")
	@PreAuthorize("hasRole('OWNER')")
	public String moderatorAccess() {
		return "Owner Board.";
	}

	@GetMapping("/admin")
	@PreAuthorize("hasRole('ADMIN')")
	public String adminAccess() {
		return "Admin Board.";
	}
}
