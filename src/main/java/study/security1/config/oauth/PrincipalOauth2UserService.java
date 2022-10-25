package study.security1.config.oauth;

import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import study.security1.config.auth.PrincipalDetails;
import study.security1.config.oauth.provider.FacebookUserInfo;
import study.security1.config.oauth.provider.GoogleUserInfo;
import study.security1.config.oauth.provider.NaverUserInfo;
import study.security1.config.oauth.provider.Oauth2UserInfo;
import study.security1.domain.User;
import study.security1.repository.UserRepository;

import java.util.Map;

@Service
@RequiredArgsConstructor
public class PrincipalOauth2UserService extends DefaultOAuth2UserService {

    private final BCryptPasswordEncoder bCryptPasswordEncoder; // 비밀번호 인코딩위해서 주입받음
    private final UserRepository userRepository;

    // oauth2 provider 로부터받은 userRequest 후처리되는 함수
    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {

        OAuth2User oAuth2User = super.loadUser(userRequest); // 프로바이더에서 제공받은 유저정보가 담겨잇음

        System.out.println("userRequest.getClientRegistration() = " + userRequest.getClientRegistration()); // 해당 유저정보의 제공자
        System.out.println("oAuth2User.getAttributes() = " + oAuth2User.getAttributes()); // 가지고 있는 모든 유저정보

        // 회원가입을 강제로 진행해볼 예정
        Oauth2UserInfo oauth2UserInfo = null; // 각각 프로바이더마다 제공해주는 정보가 다르기때문에 인터페이스로 가져올정보 공통적으로 선언하고 각각 프로바이더가 구현해서 하나로 처리
        if (userRequest.getClientRegistration().getRegistrationId().equals("google")) {
            System.out.println("구글 로그인 요청");
            oauth2UserInfo = new GoogleUserInfo(oAuth2User.getAttributes());
        } else if (userRequest.getClientRegistration().getRegistrationId().equals("facebook")) {
            System.out.println("페이스북 로그인 요청");
            oauth2UserInfo = new FacebookUserInfo(oAuth2User.getAttributes());
        } else if (userRequest.getClientRegistration().getRegistrationId().equals("naver")) {
            System.out.println("네이버 로그인 요청");
            oauth2UserInfo = new NaverUserInfo((Map) oAuth2User.getAttributes().get("response"));
        } else {
            System.out.println("우리는 구글과 페이스북과 네이버만 지원합니다.");
        }

        String username = oauth2UserInfo.getProvider() + "_" + oauth2UserInfo.getProviderId();
        String password = bCryptPasswordEncoder.encode("겟인데어"); // 단방향 해쉬에 랜덤으로 막 쓰까서 개속 다른비밀번호로 나옴 디코딩 불가능
        String role = "ROLE_USER";

        User userEntity = userRepository.findByUsername(username);

        if (userEntity == null) {
            userEntity = User.builder()
                    .username(username)
                    .password(password)
                    .email(oauth2UserInfo.getEmail())
                    .role(role)
                    .provider(oauth2UserInfo.getProvider())
                    .providerId(oauth2UserInfo.getProviderId())
                    .build();

            userRepository.save(userEntity);
        } else {
            System.out.println("로그인을 이미 한적이 있습니다. 당신은 자동회원가입이 되어 있습니다.");
        }

        return new PrincipalDetails(userEntity, oAuth2User.getAttributes());
    }
}
