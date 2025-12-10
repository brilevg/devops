#!/usr/bin/env bash
set -e

TARGET="http://localhost" 

# 1) Перебор адресов (404 / 403 simulation)
echo "=== 404 ==="
for i in $(seq 1 40); do
  curl -s -o /dev/null -w "%{http_code} %{url_effective}\n" "$TARGET/nonexistent-$RANDOM" || true
done

# 2) Много запросов с одного IP (внутренне одно и то же хост -> simulate burst)
echo "=== Burst from single IP (concurrent) ==="
seq 1 200 | xargs -I{} -P40 curl -s -o /dev/null "$TARGET/" || true
sleep 1

# 3) Подозрительные User-Agent'ы
echo "=== Suspicious User-Agents ==="
MAL_UAS=("sqlmap/1.5" "nmap-script" "masscan/1.0" "curl/7.12.0 (evil)" "() { :; }; echo exploited" "<?php system('id'); ?>" "Mozilla/5.0 (compatible; ZmEu)")
for ua in "${MAL_UAS[@]}"; do
  curl -s -A "$ua" -o /dev/null -w "UA:%{user_agent} -> %{http_code}\n" "$TARGET/" || true
done

# 4) Path traversal / LFI
echo "=== Path traversal / LFI ==="
TRAVERSALS=(
  "/../../../../etc/passwd"
  "/..%2F..%2F..%2Fetc%2Fpasswd"
)
for p in "${TRAVERSALS[@]}"; do
  curl -s -G "$TARGET$p" -o /dev/null -w "%{http_code} %s\n" || true
done

# 5) Strange headers / spoof IP (X-Forwarded-For)
echo "=== Spoofed IP headers ==="
for ip in 1.2.3.4 5.6.7.8 192.0.2.1; do
  curl -s -H "X-Forwarded-For: $ip" -A "curl-test" -o /dev/null -w "%{http_code} XFF:$ip\n" "$TARGET/" || true
done

