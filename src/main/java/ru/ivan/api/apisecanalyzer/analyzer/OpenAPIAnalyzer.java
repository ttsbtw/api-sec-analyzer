package ru.ivan.api.apisecanalyzer.analyzer;

import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.Operation;
import io.swagger.v3.oas.models.PathItem;
import io.swagger.v3.oas.models.media.Schema;
import io.swagger.v3.oas.models.security.SecurityRequirement;
import io.swagger.v3.parser.OpenAPIV3Parser;
import io.swagger.v3.parser.core.models.SwaggerParseResult;

import java.util.*;

public class OpenAPIAnalyzer {

    /**
     * Парсит OpenAPI-спецификацию из локального файла.
     */
    public static OpenAPI parseSpec(String path) {
        SwaggerParseResult result = new OpenAPIV3Parser().readLocation(path, null, null);
        if (result.getOpenAPI() == null) {
            throw new RuntimeException("Не удалось распарсить OpenAPI: " + result.getMessages());
        }
        return result.getOpenAPI();
    }

    /**
     * Анализирует OpenAPI на наличие уязвимостей из OWASP API Top 10.
     */
    public static List<String> analyze(OpenAPI openAPI) {
        List<String> issues = new ArrayList<>();

        // Проверка 1: есть ли схемы безопасности?
        boolean hasSecuritySchemes = openAPI.getComponents() != null
                && openAPI.getComponents().getSecuritySchemes() != null
                && !openAPI.getComponents().getSecuritySchemes().isEmpty();

        if (!hasSecuritySchemes) {
            issues.add("[OWASP API1] Не определены схемы безопасности (securitySchemes).");
            return issues;
        }

        // Проверка 2: эндпоинты без авторизации
        for (Map.Entry<String, PathItem> entry : openAPI.getPaths().entrySet()) {
            String path = entry.getKey();
            PathItem pathItem = entry.getValue();

            // Пропускаем легитимные публичные эндпоинты
            if (path.equals("/") ||
                    path.equals("/health") ||
                    path.equals("/openapi.json") ||
                    path.startsWith("/auth") ||
                    path.startsWith("/.well-known") ||
                    path.startsWith("/account-consents/request") ||
                    path.startsWith("/payment-consents/request") ||
                    path.startsWith("/products") ||
                    path.startsWith("/customer-leads") ||
                    path.startsWith("/product-offers/consents/request")) {
                continue;
            }

            Map<PathItem.HttpMethod, Operation> operations = pathItem.readOperationsMap();
            for (Map.Entry<PathItem.HttpMethod, Operation> opEntry : operations.entrySet()) {
                Operation operation = opEntry.getValue();
                List<SecurityRequirement> security = operation.getSecurity() != null
                        ? operation.getSecurity()
                        : openAPI.getSecurity();

                if (security == null || security.isEmpty()) {
                    String method = opEntry.getKey().name();

                    String explanation;
                    if (path.contains("/account-consents/") || path.contains("/payment-consents/")) {
                        explanation = "Этот эндпоинт управляет согласиями — доступ без авторизации может раскрыть приватные данные пользователя.";
                    } else if (path.startsWith("/internal/")) {
                        explanation = "Внутренний эндпоинт доступен публично — возможна утечка служебной информации.";
                    } else {
                        explanation = "Эндпоинт не защищён, хотя в API объявлена схема безопасности.";
                    }

                    issues.add(String.format(
                            "[%s] %s %s — %s",
                            "OWASP API1", method, path, explanation
                    ));
                }
            }
        }

        // Проверка 3: чувствительные поля (оставляем как есть, с исправлением Object → String)
        Set<String> sensitiveKeywords = Set.of(
                "password", "passwd", "secret", "token", "key", "ssn", "pin", "cvv",
                "refresh_token", "access_token", "auth", "credential", "hash", "otp"
        );

        if (openAPI.getComponents() != null && openAPI.getComponents().getSchemas() != null) {
            for (Map.Entry<String, Schema> schemaEntry : openAPI.getComponents().getSchemas().entrySet()) {
                String schemaName = schemaEntry.getKey();
                Schema schema = schemaEntry.getValue();

                if (schema.getProperties() != null) {
                    for (Object propObj : schema.getProperties().keySet()) {
                        if (propObj instanceof String propName) {
                            String lowerProp = propName.toLowerCase();
                            for (String keyword : sensitiveKeywords) {
                                if (lowerProp.contains(keyword)) {
                                    issues.add(String.format(
                                            "[OWASP API3] Схема '%s' содержит потенциально чувствительное поле: '%s'",
                                            schemaName, propName
                                    ));
                                    break;
                                }
                            }
                        }
                    }
                }
            }
        }

        return issues;
    }}