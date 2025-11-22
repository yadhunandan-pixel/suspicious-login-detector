package com.example.suspicious_login_detector.service;

import com.example.suspicious_login_detector.model.AnalysisResult;
import com.example.suspicious_login_detector.model.IpStat;
import com.example.suspicious_login_detector.model.UserStat;
import org.springframework.stereotype.Service;

import java.util.*;

@Service
public class LogAnalysisService {

    public AnalysisResult analyze(String csvContent, int threshold) {
        if (csvContent == null || csvContent.isBlank()) {
            return new AnalysisResult(0, 0, List.of(), List.of());
        }

        String[] lines = csvContent.split("\\r?\\n");
        if (lines.length <= 1) {
            return new AnalysisResult(0, 0, List.of(), List.of());
        }

        Map<String, Integer> failIp = new HashMap<>();
        Map<String, Integer> successIp = new HashMap<>();
        Map<String, Integer> failUser = new HashMap<>();
        int total = 0;

        for (int i = 1; i < lines.length; i++) {
            String line = lines[i].trim();
            if (line.isEmpty()) continue;
            String[] parts = line.split(",");
            if (parts.length < 4) continue;

            String ip = parts[1].trim();
            String user = parts[2].trim();
            String status = parts[3].trim().toUpperCase();

            total++;

            if ("FAIL".equals(status)) {
                failIp.put(ip, failIp.getOrDefault(ip, 0) + 1);
                failUser.put(user, failUser.getOrDefault(user, 0) + 1);
            } else if ("SUCCESS".equals(status)) {
                successIp.put(ip, successIp.getOrDefault(ip, 0) + 1);
            }
        }

        Set<String> allIps = new HashSet<>();
        allIps.addAll(failIp.keySet());
        allIps.addAll(successIp.keySet());

        List<IpStat> suspiciousIps = new ArrayList<>();
        for (Map.Entry<String, Integer> e : failIp.entrySet()) {
            if (e.getValue() >= threshold) {
                suspiciousIps.add(new IpStat(e.getKey(), e.getValue()));
            }
        }

        List<UserStat> attackedUsers = new ArrayList<>();
        for (Map.Entry<String, Integer> e : failUser.entrySet()) {
            if (e.getValue() >= threshold) {
                attackedUsers.add(new UserStat(e.getKey(), e.getValue()));
            }
        }

        suspiciousIps.sort(Comparator.comparingInt(IpStat::getFailedCount).reversed());
        attackedUsers.sort(Comparator.comparingInt(UserStat::getFailedCount).reversed());

        return new AnalysisResult(total, allIps.size(), suspiciousIps, attackedUsers);
    }
}
