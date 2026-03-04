package com.api.auth.security.jwtkeys;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "app.jwt.keys")
public class JwtKeysProperties {

    private String activeKid = "key1";
    private Key key1 = new Key();
    private Key key2 = new Key();

    public String getActiveKid() {
        return activeKid;
    }

    public void setActiveKid(String activeKid) {
        this.activeKid = activeKid;
    }

    public Key getKey1() {
        return key1;
    }

    public void setKey1(Key key1) {
        this.key1 = key1;
    }

    public Key getKey2() {
        return key2;
    }

    public void setKey2(Key key2) {
        this.key2 = key2;
    }

    public static final class Key {
        private String secret;

        public String getSecret() {
            return secret;
        }

        public void setSecret(String secret) {
            this.secret = secret;
        }
    }
}
