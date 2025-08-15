# file: generate_key.py
from cryptography.fernet import Fernet

# Эта команда создает криптографически стойкий ключ в нужном формате
key = Fernet.generate_key()

print("Ваш новый APP_SECRET_KEY:")
print(key.decode())