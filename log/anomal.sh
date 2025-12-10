#!/bin/bash

# Конфигурация
TARGET_URL="https://localhost:443"
NUM_REQUESTS=15
DELAY=0.1

echo "Генерация аномальных запросов к $TARGET_URL"
echo "=========================================="

# 1. Множественные ошибки 404
echo "1. Генерация 404 ошибок..."
for i in {1..50}; do
    # Случайные несуществующие пути
    random_path=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 10 | head -n 1)
    curl -k -s -o /dev/null -w "%{http_code}" \
         "$TARGET_URL/$random_path" \
         -H "User-Agent: Mozilla/5.0" \
         --max-time 2
    echo " -> GET /$random_path"
    sleep $DELAY
done

# 2. Множественные запросы с одного IP (имитация DDoS)
echo -e "\n2. Множественные запросы с одного IP..."
for i in {1..100}; do
    curl -k -s -o /dev/null \
         "$TARGET_URL/" \
         -H "User-Agent: Mozilla/5.0" \
         --max-time 1
    if (( i % 10 == 0 )); then
        echo "   Отправлено $i запросов..."
    fi
    sleep 0.05
done

# 3. Подозрительные User-Agent
echo -e "\n3. Запросы с подозрительными User-Agent..."
SUSPICIOUS_UA=(
    "sqlmap/1.5.8#stable"
    "nmap/7.80"
    "nikto/2.1.6"
    ""
    "() { :; }; echo; echo; /bin/bash -c 'cat /etc/passwd'"
    "<?php system('id'); ?>"
    "python-requests/2.25.1"
    "curl/7.74.0"
    "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)"
)

for ua in "${SUSPICIOUS_UA[@]}"; do
    curl -k -s -o /dev/null -w "User-Agent: $ua -> %{http_code}\n" \
         "$TARGET_URL/" \
         -H "User-Agent: $ua" \
         --max-time 2
    sleep $DELAY
done

# 4. XSS атаки
echo -e "\n4. Попытки XSS атак..."
XSS_PAYLOADS=(
    "<script>alert('XSS')</script>"
    "<img src=x onerror=alert(1)>"
    "javascript:alert('XSS')"
    "'\"><script>alert(1)</script>"
    "<body onload=alert('XSS')>"
)

for payload in "${XSS_PAYLOADS[@]}"; do
    encoded_payload=$(echo "$payload" | xxd -plain | tr -d '\n' | sed 's/\(..\)/%\1/g')
    curl -k -s -o /dev/null -w "XSS: $payload -> %{http_code}\n" \
         "$TARGET_URL/search?q=$encoded_payload" \
         -H "User-Agent: Mozilla/5.0" \
         --max-time 2
    sleep $DELAY
done

# 5. SQL injection атаки
echo -e "\n5. Попытки SQL injection..."
SQL_PAYLOADS=(
    "' OR '1'='1"
    "'; DROP TABLE users;--"
    "' UNION SELECT NULL--"
    "admin'--"
    "' OR SLEEP(5)--"
)

for payload in "${SQL_PAYLOADS[@]}"; do
    encoded_payload=$(echo "$payload" | xxd -plain | tr -d '\n' | sed 's/\(..\)/%\1/g')
    curl -k -s -o /dev/null -w "SQLi: $payload -> %{http_code}\n" \
         -X POST "$TARGET_URL/login" \
         -H "Content-Type: application/x-www-form-urlencoded" \
         -H "User-Agent: Mozilla/5.0" \
         -d "username=admin&password=$encoded_payload" \
         --max-time 2
    sleep $DELAY
done

# 6. Path Traversal
echo -e "\n6. Попытки Path Traversal..."
PATHS=(
    "../../../etc/passwd"
    "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts"
    "/proc/self/environ"
    "/.git/config"
    "/wp-admin/admin-ajax.php"
)

for path in "${PATHS[@]}"; do
    encoded_path=$(echo "$path" | xxd -plain | tr -d '\n' | sed 's/\(..\)/%\1/g')
    curl -k -s -o /dev/null -w "Path: $path -> %{http_code}\n" \
         "$TARGET_URL/download?file=$encoded_path" \
         -H "User-Agent: Mozilla/5.0" \
         --max-time 2
    sleep $DELAY
done

# 7. Запросы к скрытым директориям
echo -e "\n7. Сканирование скрытых директорий..."
HIDDEN_PATHS=(
    "/admin"
    "/phpmyadmin"
    "/.env"
    "/config.php"
    "/backup.zip"
    "/.git/HEAD"
    "/wp-login.php"
    "/administrator"
)

for path in "${HIDDEN_PATHS[@]}"; do
    curl -k -s -o /dev/null -w "Hidden: $path -> %{http_code}\n" \
         "$TARGET_URL$path" \
         -H "User-Agent: Mozilla/5.0" \
         --max-time 2
    sleep $DELAY
done

echo -e "\nГенерация завершена!"
