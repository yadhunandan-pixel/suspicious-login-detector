package com.example.suspicious_login_detector.model;

import java.util.List;

public class AnalysisResult {
    private int totalEntries;
    private int uniqueIps;
    private List<IpStat> suspiciousIps;
    private List<UserStat> attackedUsers;

    public AnalysisResult() {}

    public AnalysisResult(int totalEntries, int uniqueIps, List<IpStat> suspiciousIps, List<UserStat> attackedUsers) {
        this.totalEntries = totalEntries;
        this.uniqueIps = uniqueIps;
        this.suspiciousIps = suspiciousIps;
        this.attackedUsers = attackedUsers;
    }

    public int getTotalEntries() {
        return totalEntries;
    }

    public void setTotalEntries(int totalEntries) {
        this.totalEntries = totalEntries;
    }

    public int getUniqueIps() {
        return uniqueIps;
    }

    public void setUniqueIps(int uniqueIps) {
        this.uniqueIps = uniqueIps;
    }

    public List<IpStat> getSuspiciousIps() {
        return suspiciousIps;
    }

    public void setSuspiciousIps(List<IpStat> suspiciousIps) {
        this.suspiciousIps = suspiciousIps;
    }

    public List<UserStat> getAttackedUsers() {
        return attackedUsers;
    }

    public void setAttackedUsers(List<UserStat> attackedUsers) {
        this.attackedUsers = attackedUsers;
    }
}
