package com.example.suspicious_login_detector.controller;

import com.example.suspicious_login_detector.model.AnalysisResult;
import com.example.suspicious_login_detector.service.LogAnalysisService;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api")
public class AnalysisController {

    private final LogAnalysisService logAnalysisService;

    public AnalysisController(LogAnalysisService logAnalysisService) {
        this.logAnalysisService = logAnalysisService;
    }

    @PostMapping(
            value = "/analyze",
            consumes = MediaType.TEXT_PLAIN_VALUE,
            produces = MediaType.APPLICATION_JSON_VALUE
    )
    public AnalysisResult analyze(@RequestBody String csvContent,
                                  @RequestParam(defaultValue = "5") int threshold) {
        return logAnalysisService.analyze(csvContent, threshold);
    }
}
