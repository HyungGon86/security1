package study.security1;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.authentication.rememberme.PersistentTokenRepository;
import study.security1.repository.JpaPersistentTokenRepository;
import study.security1.repository.PersistentLoginRepository;

@SpringBootApplication
public class Security1Application {

	public static void main(String[] args) {
		SpringApplication.run(Security1Application.class, args);
	}

	@Bean
	public BCryptPasswordEncoder encodePwd() {
		return new BCryptPasswordEncoder();
	}

	@Bean // PersistentTokenRepository 등록 PersistentLoginRepository DI로 주입받아서 해당 빈 등록
	public PersistentTokenRepository persistentTokenRepository(PersistentLoginRepository repository) {
		return new JpaPersistentTokenRepository(repository);
	}

}
