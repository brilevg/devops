# Введение
Это веб-приложение - библиотека. В ней можно добавлять, менять, удалять книги. Работает через веб-интерфейс и принимает запросы по API.

# Установка

Лучше всего работает на Debian. Перед началом выполнения всех действий сделайте снапшот вашей виртуальной машины. Для выполнения программы необходимо не менее 30 Gb свободного места.

Для начала необходимо установить docker-compose и docker.io:

```bash
sudo apt install docker-compose docker.io curl
```

# Запуск
Клонируйте репозиторий:
```bash
git clone https://github.com/brilevg/devops.git
```
Перейдите в папку devops
```bash
cd devops
```

Создадите ключи для nginx
```bash
sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout nginx/ssl.key \
  -out nginx/ssl.crt \
  -subj "/C=RU/ST=Prim/L=VLAD/O=FEFU/OU=STUDENT/CN=localhost"
```

Создайте файл .env и укажите:
```
FLASK_SECRET_KEY=secret-key
POSTGRES_HOST=postgres
POSTGRES_PORT=5432
POSTGRES_DB=db
POSTGRES_USER=user
POSTGRES_PASSWORD=password

MONGO_HOST=mongodb
MONGO_PORT=27017
MONGO_DB=book_db
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

Отправьте запросы через curl

Увидите список всех книг: 
```bash
curl -v -k -X GET http://localhost:443/api/books
```

Создайте новую книгу:
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

Теперь увидите саму книгу.
Замените {id} на реальный ID из ответа POST запроса:
```bash
curl -v -k -X GET https://localhost:443/api/books/{id}
```

Обновите книгу:
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

Удалите книгу:
```bash
curl -v -k -X DELETE http://localhost:8000/api/books/{id}
```

## Gitlab

В /etc/hosts добавьте запись:

```
127.0.0.1 gitlab.local
```
Создайте папку gitlab в папке devops:
```bash
mkdir -p gitlab
```

Создайте два ключа:
```bash
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout gitlab/gitlab.local.key \
  -out gitlab/gitlab.local.crt \
  -subj "/CN=gitlab.local"
```
```bash
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout gitlab/registry.gitlab.local.key \
  -out gitlab/registry.gitlab.local.crt \
  -subj "/CN=registry.gitlab.local"
```
Остановите приложение для запуска gitlab. Запускается gitlab командой:

```bash
sudo docker-compose -f docker-compose.gitlab.yml up --build
```
Gitlab запускает не менее 10 минут.

Проверка доступа:
```bash
curl -k -I https://gitlab.local/users/sign_in
```






