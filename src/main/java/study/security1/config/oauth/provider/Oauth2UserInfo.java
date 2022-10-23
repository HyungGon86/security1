package study.security1.config.oauth.provider;

public interface Oauth2UserInfo {
    String getProvider();

    String getProviderId();

    String getEmail();

    String getName();
}
