package app.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;
import java.util.Map;

@RestController
public class HomeController {

    @GetMapping
    public Map<String, String> home(Principal principal) {
        return Map.of("message", "Welcome to the API", "username", principal.getName());
    }

    @GetMapping("/profile")
    public String profile(Principal principal) {
        System.out.println(principal);
        return principal.toString();
    }
}
