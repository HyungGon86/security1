package study.security1.domain;

import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.springframework.security.web.authentication.rememberme.PersistentRememberMeToken;

import javax.persistence.*;
import java.util.Date;

@Entity
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class PersistentLogin {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "persistent_login_id")
    private Long id;

    private String series;

    private String username;

    private String token;

    private Date lastUsed;

    private PersistentLogin(PersistentRememberMeToken token) {
        this.series = token.getSeries();
        this.username = token.getUsername();
        this.token = token.getTokenValue();
        this.lastUsed = token.getDate();
    }

    public static PersistentLogin from(PersistentRememberMeToken token) {
        return new PersistentLogin(token);
    }

    public void updateToken(String tokenValue, Date lastUsed) {
        this.token = tokenValue;
        this.lastUsed = lastUsed;
    }
}
