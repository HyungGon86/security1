package study.security1.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import study.security1.domain.PersistentLogin;

import java.util.List;
import java.util.Optional;

public interface PersistentLoginRepository extends JpaRepository<PersistentLogin, Long> {

    Optional<PersistentLogin> findBySeries(String series);

    List<PersistentLogin> findByUsername(String username);

}
