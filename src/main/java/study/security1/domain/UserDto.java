package study.security1.domain;

import lombok.Data;

import javax.validation.constraints.NotBlank;

@Data
public class UserDto {

    @NotBlank(message = "아이디를 입력해주세요.")
    private String username;
    private String password;
    private String email;

    public UserDto() {
    }

    public UserDto(String username, String password, String email) {
        this.username = username;
        this.password = password;
        this.email = email;
    }
}
