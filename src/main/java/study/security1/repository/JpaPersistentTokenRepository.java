package study.security1.repository;

import org.springframework.security.web.authentication.rememberme.PersistentRememberMeToken;
import org.springframework.security.web.authentication.rememberme.PersistentTokenRepository;
import org.springframework.transaction.annotation.Transactional;
import study.security1.domain.PersistentLogin;

import java.util.Date;


public class JpaPersistentTokenRepository implements PersistentTokenRepository {

    private final PersistentLoginRepository persistentLoginRepository; // PersistentTokenRepository 빈 등록하면서 컴포지션으로 주입

    public JpaPersistentTokenRepository(PersistentLoginRepository persistentLoginRepository) {
        this.persistentLoginRepository = persistentLoginRepository;
    }

    // 새로운 remember-me 쿠키를 발급할 때 담을 토큰을 생성하기 위한 메서드
    @Override
    public void createNewToken(PersistentRememberMeToken token) {
        System.out.println("리멤버미 토큰 생성");
        persistentLoginRepository.save(PersistentLogin.from(token));
    }

    // 토큰을 변경할 때 호출될 메서드
    @Override
    @Transactional // 더티체킹으로 업데이트 날려주려고 트랜잭션 어노테이션 추가해줌
    public void updateToken(String series, String tokenValue, Date lastUsed) {
        System.out.println("리멤버미 토큰 업데이트");
        persistentLoginRepository.findBySeries(series)
                .ifPresent(persistentLogin ->
                    persistentLogin.updateToken(tokenValue, lastUsed)
                );
    }

    // 사용자에게서 remember-me 쿠키를 이용한 인증 요청이 들어올 경우 호출될 메서드
    // 사용자가 보낸 쿠키에 담긴 시리즈로 데이터베이스를 검색해 토큰을 찾는다
    @Override
    public PersistentRememberMeToken getTokenForSeries(String seriesId) {
        System.out.println("리멤버미 토큰 참조");
        return persistentLoginRepository.findBySeries(seriesId) // 반환값 옵셔널 맵으로 PersistentRememberMeToken으로 변환해서 리턴
                .map(persistentLogin ->
                    new PersistentRememberMeToken(
                            persistentLogin.getUsername(),
                            persistentLogin.getSeries(),
                            persistentLogin.getToken(),
                            persistentLogin.getLastUsed()
                    )
                ).orElseThrow(IllegalArgumentException::new);
    }

    // 세션이 종료될 경우 데이터베이스에서 영구 토큰을 제거
    @Override
    public void removeUserTokens(String username) {
        System.out.println("리멤버미 토큰 삭제");
        persistentLoginRepository.deleteAllInBatch(persistentLoginRepository.findByUsername(username));
    }
}
