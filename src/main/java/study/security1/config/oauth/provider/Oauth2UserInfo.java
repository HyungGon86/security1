package study.security1.config.oauth.provider;

public interface Oauth2UserInfo { // 프로바이더 마다 제공해주는 키값이 다 달라서 인터페이스 구현해서 다형성으로 처리하면 편함
    String getProvider();

    String getProviderId();

    String getEmail();

    String getName();
}
