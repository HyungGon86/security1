package study.security1.config.auth;

import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import study.security1.domain.User;
import study.security1.repository.UserRepository;

// 시큐리티 설정에서 /login 요청이 오면
// 자동으로 UserDetailService 타입으로 Ioc되어 있는 loadUserByUsername 함수가 실행

@Service
@RequiredArgsConstructor
public class PrincipalDetailService implements UserDetailsService {

    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User loginUser = userRepository.findByUsername(username);
        return loginUser != null ? new PrincipalDetails(loginUser) : null;
    }
}
