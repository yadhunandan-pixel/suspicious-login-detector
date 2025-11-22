package com.example.suspicious_login_detector.model;

public class IpStat {
    private String ip;
    private int failedCount;

    public IpStat() {}

    public IpStat(String ip, int failedCount) {
        this.ip = ip;
        this.failedCount = failedCount;
    }

    public String getIp() {
        return ip;
    }

    public void setIp(String ip) {
        this.ip = ip;
    }

    public int getFailedCount() {
        return failedCount;
    }

    public void setFailedCount(int failedCount) {
        this.failedCount = failedCount;
    }
}
