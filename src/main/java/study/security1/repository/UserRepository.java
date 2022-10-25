package study.security1.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import study.security1.domain.User;

public interface UserRepository extends JpaRepository<User, Long> {

    User findByUsername(String username);

    boolean existsByUsername(String username);
}
