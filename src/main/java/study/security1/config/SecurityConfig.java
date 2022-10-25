package study.security1.config;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.authentication.rememberme.JdbcTokenRepositoryImpl;
import org.springframework.security.web.authentication.rememberme.PersistentRememberMeToken;
import org.springframework.security.web.authentication.rememberme.PersistentTokenRepository;
import study.security1.config.auth.PrincipalDetailService;
import study.security1.config.oauth.PrincipalOauth2UserService;
import study.security1.repository.JpaPersistentTokenRepository;
import study.security1.repository.PersistentLoginRepository;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Date;

// 구글 로그인이 완료된 뒤의 후처리가 필요함
// 1.코드받기 2.엑세스토큰(권한) 3.사용자프로필 정보를 가져오고
// 4.그 정보를 토대로 회원가입을 자동으로 진행시키기도 함
// Tip 구글 로그인이 완료되면 코드X (액세스토큰+사용자프로필정보 한방에 줌)

@RequiredArgsConstructor
@Configuration
@EnableWebSecurity // 스프링 시큐리티 필터가 스프링 필터체인에 등록됨
@EnableGlobalMethodSecurity(securedEnabled = true, prePostEnabled = true) // secured 어노테이션 활성화, preAuthorize 어노테이션 활성화
public class SecurityConfig {

    private final PrincipalOauth2UserService principalOauth2UserService;
    private final AuthenticationFailureHandler customFailureHandler;

    private final UserDetailsService userDetailsService; // 해당 유저디테일서비스 인터페이스를 PrincipalDetailService 구현하고 등록해서 다형성으로 주입받음
    private final PersistentTokenRepository tokenRepository; // 위에 유저디테일서비스와 마찬가지 결합도를 낮추고 유연성을 증가시키기위함

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.csrf().disable();
        http.authorizeRequests()
                .antMatchers("/user/**").authenticated() // 인증만 되면 접속가능
                .antMatchers("/manager/**").access("hasAnyRole('ROLE_MANAGER','ROLE_ADMIN')") // 매니저나 어드민 권한이 잇어야 접속가능
                .antMatchers("/admin/**").access("hasRole('ROLE_ADMIN')") // 어드민만 접속가능
                .anyRequest().permitAll() // 그 외 요청은 누구나 접속가능함
                .and()
                .formLogin() // formLogin 활성화
                .loginPage("/loginForm") // 기본적인 로그인페이지 설정
                .loginProcessingUrl("/login") // /login 주소가 호출이 되면 시큐리티가 낚아채서 로그인을 진행해줌
                .failureHandler(customFailureHandler) // 로그인 실패시 호출할 커스텀 핸들러 AuthenticationFailureHandler 인터페이스를 구현한 객체가 DI 로 주입
                .defaultSuccessUrl("/") // 기본 로그인페이지로 들어올시 해당 주소로 롤백해주고 다른 주소로 접근해서 로그인시 해당주소로 보내줌
                .and()
                .exceptionHandling() // 오류났을 때 핸들링여부
                .accessDeniedPage("/e403") // 접근 거부됐을 때 리턴해줄 페이지 좀 더 유연하게 바꾸고 싶으면 handler 인터페이스 구현해서 꾸며도댐
                .and()
                .logout() // 로그아웃 설정시작
                .deleteCookies("JSESSIONID", "remember-me") // 저장된 쿠키삭제처리
                .invalidateHttpSession(true) // 서버에 남아있는 세션정보 날려버리기
                .logoutSuccessHandler(new LogoutSuccessHandler() { // 로그아웃이후 리턴해주는 설정
                    @Override
                    public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
                        response.sendRedirect(request.getHeader("referer") == null ? "/" : request.getHeader("referer"));
                    }
                })
                .and()
                .oauth2Login() // oauth2 로그인 활성화
                .loginPage("/loginForm") // oauth2 로그인 페이지 기본 설정
                .userInfoEndpoint() // 로그인 성공 후 사용자 정보를 가져올 설정 담당
                .userService(principalOauth2UserService); // userService 에서 가져올거고 매개변수 타입 클래스 상속받아서 커스텀으로 구현해줫음

        http.rememberMe()
                .rememberMeParameter("remember-me") // 기본 파라미너명은 remember-me
                .tokenValiditySeconds(10) // 리멤버미지속시간 default는 14일
                .userDetailsService(userDetailsService) // 시스템에 있는 사용자 계정을 조회할 때 사용할 클래스
                .tokenRepository(tokenRepository); // PersistentTokenRepository 구현체넣어줘야댐 커스텀한다는 메서드

        // 동시 세션 제어
        http.sessionManagement(session -> session
                        .maximumSessions(1)
                        .maxSessionsPreventsLogin(false)
        );
//                .maximumSessions(1); // 허용 가능 세션 수 -1 넣으면 무제한 생성
//                .maxSessionsPreventsLogin(false); // false : 이전 사용자 세션 만료 / true : 현재 사용자 인증 실패
//                .invalidSessionUrl("/invalid") // 세션 유효하지 않을 때 이동할 페이지
//                .expiredUrl("/expired"); // 세션이 만료된 경우 이동할 페이지

        // invalidSessionUrl 과 expiredUrl 둘 다 설정된 경우
        // invalidSessionUrl 이 우선순위를 갖는다고 함...


//        http.sessionManagement() // 세션 고정 보호 설정 코드
//                .sessionFixation()
//                .changeSessionId();
        //해당 기능은 따로 설정을 하지 않아도 Spring Security가 기본적으로 적용.

        return http.build();
    }

}
