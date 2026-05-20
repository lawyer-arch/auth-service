.PHONY: db-start db-stop start

# Запуск сервиса на Poetry
start:
	@echo "Запуск сервиса на Poetry..."
	@poetry run python src/main.py # замените src/main.py на ваш основной файл

# Проверка статуса PostgreSQL
db-status:
	@echo "Проверка статуса PostgreSQL..."
	@sudo ss -tulnp | grep 5432

# Перезапуск PostgreSQL (если что-то пошло не так)
db-restart:
	@echo "Перезапуск PostgreSQL..."
	@sudo systemctl restart postgresql

# Остановка PostgreSQL
db-stop:
	@echo "Остановка PostgreSQL..."
	@sudo systemctl stop postgresql

# Запуск PostgreSQL (если не запущен)
db-start:
	@echo "Запуск PostgreSQL..."
	@sudo systemctl start postgresql


migration:
	@echo "Инициализируем миграции..."
	poetry run alembic revision --autogenerate -m "initial"

migrate:
	@echo "Применяем миграции..."
	poetry run alembic upgrade head