# Введение
Это веб-приложение - библиотека. В ней можно добавлять, менять, удалять книги. Работает через веб-интерфейс и принимает запросы по API.

# Установка

Лучше всего работает на Debian. Перед началом выполнения всех действий сделайте снапшот вашей виртуальной машины. Для выполнения программы необходимо не менее 30 Gb свободного места.

Для начала необходимо установить docker-compose и docker.io:

```bash
sudo apt install docker-compose docker.io curl
```

# Запуск

Переходим в папку server
```bash
cd devops
```

Создадим ключи для nginx
```bash
sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout nginx/ssl.key \
  -out nginx/ssl.crt \
  -subj "/C=RU/ST=Prim/L=VLAD/O=FEFU/OU=STUDENT/CN=localhost"
```

Запускается приложение в 3 разных вариантах: для fake БД, postgres и mongo. Одновременно запускать нельзя.
```bash
 sudo DB_TYPE=fake ./compose.sh up --build
```
```bash
 sudo DB_TYPE=postgres ./compose.sh up --build
```
```bash
 sudo DB_TYPE=mongo ./compose.sh up --build
```
В итоге запустится приложение на localhost:443

# Тестирование

Отправим запросы через curl

Увидим список всех книг. 
```bash
curl -v -k -X GET http://localhost:8000/api/books
```

Создадим новую книгу.
```bash
curl -v -k -X POST https://localhost:443/api/books \
  -H "Content-Type: application/json" \
  -d '{
    "title": "test",
    "author": "test",
    "year": 1234,
    "description": "123"
  }'
```

Теперь увидим саму книгу.
Замените {id} на реальный ID из ответа POST запроса
```bash
curl -v -k -X GET https://localhost:443/api/books/{id}
```

Обновим книгу.
```bash
curl -v -k -X PUT https://localhost:443/api/books/{id} \
  -H "Content-Type: application/json" \
  -d '{
    "title": "new test",
    "author": "new test",
    "year": 1235,
    "description": "1"
  }'
```

Удалим книгу.
```bash
curl -v -k -X DELETE http://localhost:8000/api/books/{id}
```

## Gitlab

В /etc/hosts добавить запись:

```
127.0.0.1 gitlab.local
```

Остановите приложение для запуска gitlab. Запускается gitlab командой:

```bash
sudo docker-compose -f docker-compose.gitlab.yml up --build
```

Проверка доступа
```bash
curl -k -I https://gitlab.local/users/sign_in
```

