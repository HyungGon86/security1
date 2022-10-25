package study.security1;

import lombok.RequiredArgsConstructor;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.Errors;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;
import study.security1.config.auth.PrincipalDetails;
import study.security1.domain.User;
import study.security1.domain.UserDto;
import study.security1.repository.UserRepository;

@Controller
@RequiredArgsConstructor
public class IndexController {

    private final UserRepository userRepository;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    @GetMapping("/test/login")
    @ResponseBody
    public String testLogin(Authentication authentication) {
        PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();
        System.out.println("principalDetails = " + principalDetails.getUser());
        return "세션 정보 확인하기";
    }

    @GetMapping("/")
    public String index() {
        return "index";
    }

    @GetMapping("/user")
    public String user(@AuthenticationPrincipal PrincipalDetails principalDetails) {
        System.out.println("principalDetails.getUser() = " + principalDetails.getUser());

        return "user";
    }

    @GetMapping("/admin")
    @ResponseBody
    public String admin() {
        return "admin";
    }

    @GetMapping("/manager")
    @ResponseBody
    public String manager() {
        return "manager";
    }

    @GetMapping("/loginForm")
    public String loginForm() {
        return "loginForm";
    }

    @GetMapping("/joinForm")
    public String joinForm(Model model) {
        model.addAttribute("userDto", new UserDto());

        return "joinForm";
    }

    @PostMapping("/join")
    public String join(@Validated @ModelAttribute UserDto userDto, Errors errors) {

        boolean duplicateId = userRepository.existsByUsername(userDto.getUsername());
        System.out.println("errors = " + errors);

        if (errors.hasErrors()) {
            return "joinForm";
        }

        if (duplicateId) {
            errors.rejectValue("username", "duplicateId", "이미 사용중인 아이디입니다.");
            return "joinForm";
        }

        String encPassword = bCryptPasswordEncoder.encode(userDto.getPassword());

        User user = User.builder()
                .username(userDto.getUsername())
                .password(encPassword)
                .email(userDto.getEmail())
                .role("ROLE_USER")
                .build();

        userRepository.save(user);
        return "redirect:/loginForm";
    }

    @Secured("ROLE_ADMIN") // 표현식을 사용할 수 없고 OR 문만 표현가능 권한 있어야 접근가능 메서드단위로 적용
    @GetMapping("/info")
    @ResponseBody
    public String info() {
        return "개인정보";
    }

    @PreAuthorize("hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')") // Spring EL(표현식)을 사용할 수 있고, AND나 OR 같은 표현식을 사용가능
    @GetMapping("/data")
    @ResponseBody
    public String data() {
        return "데이터정보";
    }

    @GetMapping("/auth/login")
    public String login(@RequestParam(required = false) String error,
                        @RequestParam(required = false) String exception,
                        RedirectAttributes rttr) {

        rttr.addFlashAttribute("error", error);
        rttr.addFlashAttribute("exception", exception);

        return "redirect:/loginForm";
    }

    @GetMapping("/e403")
    public String e403() {
        return "error/4xx";
    }

}

