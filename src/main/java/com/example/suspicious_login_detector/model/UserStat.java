package com.example.suspicious_login_detector.model;

public class UserStat {
    private String username;
    private int failedCount;

    public UserStat() {}

    public UserStat(String username, int failedCount) {
        this.username = username;
        this.failedCount = failedCount;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public int getFailedCount() {
        return failedCount;
    }

    public void setFailedCount(int failedCount) {
        this.failedCount = failedCount;
    }
}
