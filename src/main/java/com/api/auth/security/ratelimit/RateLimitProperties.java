package com.api.auth.security.ratelimit;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "app.security.ratelimit")
public class RateLimitProperties {

    private boolean enabled = true;
    private Login login = new Login();
    private Refresh refresh = new Refresh();
    private Penalty penalty = new Penalty();

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public Login getLogin() {
        return login;
    }

    public void setLogin(Login login) {
        this.login = login;
    }

    public Refresh getRefresh() {
        return refresh;
    }

    public void setRefresh(Refresh refresh) {
        this.refresh = refresh;
    }

    public Penalty getPenalty() {
        return penalty;
    }

    public void setPenalty(Penalty penalty) {
        this.penalty = penalty;
    }

    public static final class WindowedLimit {
        private long capacity;
        private long windowSeconds;

        public WindowedLimit() {
        }

        public WindowedLimit(long capacity, long windowSeconds) {
            this.capacity = capacity;
            this.windowSeconds = windowSeconds;
        }

        public long getCapacity() {
            return capacity;
        }

        public void setCapacity(long capacity) {
            this.capacity = capacity;
        }

        public long getWindowSeconds() {
            return windowSeconds;
        }

        public void setWindowSeconds(long windowSeconds) {
            this.windowSeconds = windowSeconds;
        }
    }

    public static final class Login {
        private WindowedLimit ip = new WindowedLimit(10, 60);
        private WindowedLimit principal = new WindowedLimit(5, 60);

        public WindowedLimit getIp() {
            return ip;
        }

        public void setIp(WindowedLimit ip) {
            this.ip = ip;
        }

        public WindowedLimit getPrincipal() {
            return principal;
        }

        public void setPrincipal(WindowedLimit principal) {
            this.principal = principal;
        }
    }

    public static final class Refresh {
        private WindowedLimit ip = new WindowedLimit(30, 60);

        public WindowedLimit getIp() {
            return ip;
        }

        public void setIp(WindowedLimit ip) {
            this.ip = ip;
        }
    }

    public static final class Penalty {
        private boolean enabled = true;
        private long cooldownSeconds = 300;

        public boolean isEnabled() {
            return enabled;
        }

        public void setEnabled(boolean enabled) {
            this.enabled = enabled;
        }

        public long getCooldownSeconds() {
            return cooldownSeconds;
        }

        public void setCooldownSeconds(long cooldownSeconds) {
            this.cooldownSeconds = cooldownSeconds;
        }
    }
}
