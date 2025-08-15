# 🚀 Altrina - Платформа для создания Telegram-ботов

Altrina - это современная платформа для создания и управления Telegram-ботами без необходимости написания кода. Создавайте ботов для вашего бизнеса за 5 минут!

## ✨ Возможности

- 🤖 **Создание ботов за 5 минут** - готовые шаблоны для разных типов бизнеса
- 📅 **Онлайн-запись** - автоматическое бронирование и управление расписанием
- 💬 **FAQ и поддержка** - автоматические ответы на частые вопросы
- 🔔 **Напоминания** - уведомления клиентам о записях
- 📊 **Аналитика** - подробная статистика и отчеты
- 🔐 **OAuth авторизация** - вход через Яндекс и ВКонтакте
- 📱 **Адаптивный дизайн** - работает на всех устройствах

## 🛠 Технологии

- **Frontend**: Next.js 14, React, TypeScript, Tailwind CSS
- **Backend**: Python FastAPI (в разработке)
- **База данных**: SQLite (разработка), PostgreSQL (production)
- **Авторизация**: JWT + OAuth (Яндекс, ВКонтакте)
- **UI компоненты**: Lucide Icons, Custom Components

## 🚀 Быстрый старт

### Предварительные требования

- Node.js 18+ 
- pnpm или npm
- Python 3.8+ (для backend)

### Установка

1. **Клонируйте репозиторий**
```bash
git clone https://github.com/yourusername/altrina.git
cd altrina
```

2. **Установите зависимости**
```bash
# Frontend
cd apps/web
pnpm install

# Backend (опционально)
cd ../api
pip install -r requirements.txt
```

3. **Настройте переменные окружения**
```bash
# Скопируйте пример файла
cp env.example .env.local

# Заполните ваши данные
YANDEX_CLIENT_ID=your_yandex_client_id
YANDEX_CLIENT_SECRET=your_yandex_client_secret
YANDEX_REDIRECT_URI=http://localhost:3000/api/auth/yandex/callback
```

4. **Запустите проект**
```bash
# Frontend
cd apps/web
pnpm dev

# Backend (опционально)
cd ../api
python main.py
```

5. **Откройте в браузере**
```
http://localhost:3000
```

## 🔐 Настройка OAuth

### Яндекс OAuth
1. Перейдите на [Яндекс OAuth](https://oauth.yandex.ru/client/new)
2. Создайте приложение с callback URL: `http://localhost:3000/api/auth/yandex/callback`
3. Получите Client ID и Client Secret
4. Добавьте в `.env.local`

### ВКонтакте OAuth
1. Перейдите на [VK Developers](https://vk.com/dev)
2. Создайте Standalone приложение
3. Настройте Redirect URI: `http://localhost:3000/api/auth/vk/callback`
4. Получите Application ID и Secure Key
5. Добавьте в `.env.local`

## 📁 Структура проекта

```
altrina/
├── apps/
│   ├── web/                 # Next.js frontend
│   │   ├── src/
│   │   │   ├── app/        # App Router
│   │   │   ├── components/ # UI компоненты
│   │   │   └── lib/        # Утилиты и API
│   │   └── public/         # Статические файлы
│   └── api/                # Python FastAPI backend
├── packages/                # Общие пакеты
└── docs/                   # Документация
```

## 🎨 UI Компоненты

- **Logo** - логотип с настройками размера
- **OAuthButton** - кнопки для OAuth провайдеров
- **Divider** - разделитель с текстом
- **OAuthError** - отображение ошибок OAuth

## 🔒 Безопасность

- ✅ Переменные окружения для секретных данных
- ✅ CSRF защита через state параметры
- ✅ Валидация всех входящих данных
- ✅ Безопасные OAuth endpoints
- ✅ .gitignore настроен для защиты секретов

## 📱 Страницы

- **Главная** (`/`) - лендинг с описанием возможностей
- **Вход** (`/login`) - авторизация через OAuth или email
- **Регистрация** (`/register`) - создание аккаунта
- **Dashboard** (`/dashboard`) - управление ботами
- **Аналитика** (`/dashboard/analytics`) - статистика и отчеты
- **Условия** (`/terms`) - публичная оферта
- **Конфиденциальность** (`/privacy`) - политика обработки данных

## 🚧 В разработке

- [ ] Backend API на FastAPI
- [ ] База данных пользователей
- [ ] Создание и управление ботами
- [ ] Telegram Bot API интеграция
- [ ] Система платежей
- [ ] Мобильное приложение

## 🤝 Вклад в проект

1. Fork репозитория
2. Создайте feature branch (`git checkout -b feature/amazing-feature`)
3. Commit изменения (`git commit -m 'Add amazing feature'`)
4. Push в branch (`git push origin feature/amazing-feature`)
5. Откройте Pull Request

## 📄 Лицензия

Этот проект лицензирован под MIT License - см. файл [LICENSE](LICENSE) для деталей.

## 📞 Поддержка

- **Email**: support@altrina.ru
- **Telegram**: @altrina_support
- **Документация**: [docs.altrina.ru](https://docs.altrina.ru)

## 🙏 Благодарности

- [Next.js](https://nextjs.org/) - React framework
- [Tailwind CSS](https://tailwindcss.com/) - CSS framework
- [Lucide](https://lucide.dev/) - Icon library
- [FastAPI](https://fastapi.tiangolo.com/) - Python web framework

---

**Сделано с ❤️ командой Altrina**
