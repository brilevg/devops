# Используем официальный python-образ
FROM python:3.13.9

# Рабочая директория контейнера
WORKDIR /app

# Устанавливаем uv — современный пакетный менеджер
RUN pip install uv

# Копируем описание зависимостей
COPY pyproject.toml .

# Устанавливаем зависимости через uv
RUN uv sync

# Копируем приложение
COPY . .

# Запускаем приложение через uv run python app.py
CMD ["uv", "run", "python", "app.py"]
