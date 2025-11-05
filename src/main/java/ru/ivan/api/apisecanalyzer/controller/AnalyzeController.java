package ru.ivan.api.apisecanalyzer.controller;

import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import ru.ivan.api.apisecanalyzer.analyzer.OpenAPIAnalyzer;
import io.swagger.v3.oas.models.OpenAPI;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Map;

@RestController
@RequestMapping("/api")
public class AnalyzeController {

    @PostMapping("/analyze")
    public Map<String, Object> analyze(@RequestParam("file") MultipartFile file) {
        try {
            Path tempFile = Files.createTempFile("openapi", ".yaml");
            Files.write(tempFile, file.getBytes());

            OpenAPI spec = OpenAPIAnalyzer.parseSpec(tempFile.toString());
            var issues = OpenAPIAnalyzer.analyze(spec);

            return Map.of(
                    "success", true,
                    "issues", issues,
                    "message", "Анализ завершён"
            );
        } catch (Exception e) {
            return Map.of(
                    "success", false,
                    "error", e.getMessage()
            );
        }
    }
}