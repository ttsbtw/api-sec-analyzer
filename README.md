# API Security Analyzer

Автоматизированный инструмент анализа безопасности OpenAPI-спецификаций, совместимый с CI/CD.  
Разработан для хакатона VTB API: Защита API и автоматический анализ уязвимостей!

## Возможности

- Анализ OpenAPI (YAML/JSON) на соответствие OWASP API Top 10:
    - API1: Broken Object Level Authorization — поиск эндпоинтов без авторизации.
    - API3: Excessive Data Exposure — обнаружение чувствительных полей (`password`, `token`, `ssn` и др.).
- Поддержка CLI и JSON-отчётов для интеграции в CI/CD.
- Учёт специфики Open Banking (например, публичные `/auth`, `/products`, `/consents/request`).

### 1. Сборка
В bash пропишите:
./mvnw clean package

### 2. Анализ через консоль
В bash пропишите:
java -jar target/api-sec-analyzer-0.0.1.jar openapi.yaml (ваш API)

### 3. Анализ c JSON выводом:
В bash пропишите:
java -jar target/api-sec-analyzer-0.0.1.jar openapi.yaml --format json

### Примеры вывода:
ТЕКСТ:
[OWASP API1] GET /account-consents/{consent_id} — Этот эндпоинт управляет согласиями — доступ без авторизации может раскрыть приватные данные пользователя.
JSON:
{
    "issues_count": 2,
    "success": false,
    "issues": [
    "[OWASP API1] GET /account-consents/{consent_id} — ..."
    ]
}

### Технологический стэк

- Java 17
- Spring Boot (jar)
- Swagger Parser (parsing)
- OWASP API Top 10 (взяли API1 & API3)