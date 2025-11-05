package ru.ivan.api.apisecanalyzer;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import ru.ivan.api.apisecanalyzer.analyzer.OpenAPIAnalyzer;
import io.swagger.v3.oas.models.OpenAPI;

import java.util.List;
import java.util.Map;

@SpringBootApplication
public class SpringInitApplication implements CommandLineRunner {

    public static void main(String[] args) {
        if (args.length == 0) {
            SpringApplication.run(SpringInitApplication.class, args);
            return;
        }

        String specPath = args[0];
        boolean jsonFormat = false;

        // Поддержка --format json
        for (String arg : args) {
            if ("--format".equals(arg)) {
                // Пропускаем, обработаем ниже
            } else if ("json".equals(arg)) {
                jsonFormat = true;
            }
        }

        try {
            OpenAPI spec = OpenAPIAnalyzer.parseSpec(specPath);
            List<String> issues = OpenAPIAnalyzer.analyze(spec);

            if (jsonFormat) {
                reportAsJson(issues);
            } else {
                reportAsText(issues);
            }
        } catch (Exception e) {
            if (jsonFormat) {
                System.out.println("{\"error\": \"" + e.getMessage().replace("\"", "\\\"") + "\"}");
            } else {
                System.err.println("Ошибка: " + e.getMessage());
            }
            System.exit(1);
        }

        System.exit(0);
    }

    private static void reportAsText(List<String> issues) {
        System.out.println("Анализ завершён.");
        if (issues.isEmpty()) {
            System.out.println("Нет найденных уязвимостей.");
        } else {
            System.out.println("Найдены проблемы:");
            issues.forEach(System.out::println);
        }
    }

    private static void reportAsJson(List<String> issues) throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        mapper.enable(SerializationFeature.INDENT_OUTPUT);

        Map<String, Object> report = Map.of(
                "tool", "API Security Analyzer",
                "spec", "input OpenAPI file",
                "issues_count", issues.size(),
                "issues", issues,
                "success", issues.isEmpty()
        );

        System.out.println(mapper.writeValueAsString(report));
    }

    @Override
    public void run(String... args) throws Exception {
        System.out.println("✅ Spring Boot API запущен на http://localhost:8080");
    }
}