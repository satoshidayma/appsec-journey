# JWT: уязвимая и безопасная версия проверки токена

Учебный проект на Go (`github.com/golang-jwt/jwt/v5`), показывающий разницу
между небезопасной и безопасной проверкой JWT. Две отдельные программы:

- **`vuln/`** — порт `8080`, проверка токена без ограничений (алгоритм, exp, iss, aud).
- **`fixed/`** — порт `8081`, та же логика, но с полной валидацией.

Оба используют один и тот же HMAC-секрет (`"secret"`) и один тестовый
пользователь: `alice / alice`.

## Запуск

Каждая версия — отдельный Go-модуль, запускаются независимо и могут работать
одновременно (разные порты).

```bash
# уязвимая версия (порт 8080)
cd vuln
go mod tidy
go run .

# безопасная версия (порт 8081), в другом терминале
cd fixed
go mod tidy
go run .
```

Проверка вручную:

```bash
curl -s -X POST localhost:8080/login -d '{"username":"alice","password":"alice"}'
curl -s -X POST localhost:8081/login -d '{"username":"alice","password":"alice"}'
```

Эндпоинты у обеих версий одинаковые:

| Метод | Путь | Описание |
|---|---|---|
| `POST` | `/login` | выдаёт токен по логину/паролю |
| `GET` | `/protected` | требует `Authorization: Bearer <token>`, возвращает claims |

## Автоматические тесты

В каждой папке лежит `test.sh` — сам собирает бинарь, поднимает сервер,
прогоняет 5 проверок и глушит сервер в конце.

```bash
./vuln/test.sh    # все 5 тестов должны быть PASS (атаки ПРОХОДЯТ — это демонстрация дырок)
./fixed/test.sh   # все 5 тестов должны быть PASS (атаки ОТКЛОНЯЮТСЯ)
```

## Какие уязвимости разобраны

Все четыре живут в одной функции — `ParseToken` — и решаются набором опций
`jwt.ParseWithClaims` из `golang-jwt/v5`.

### 1. Отсутствие ограничения на алгоритм подписи

**Проблема (`vuln`):** `keyFunc` сам решает, что делать с любым алгоритмом,
который прислал клиент, и явно разрешает `alg: none`:

```go
func(t *jwt.Token) (any, error) {
    if t.Method == jwt.SigningMethodNone {
        return jwt.UnsafeAllowNoneSignatureType, nil
    }
    return jwtSecret, nil
}
```

Атакующий присылает токен с заголовком `{"alg":"none"}` и пустой подписью —
сервер принимает его как валидный, потому что проверки алгоритма нет вовсе.

**Фикс (`fixed`):** жёсткий список допустимых алгоритмов передаётся прямо в
`ParseWithClaims`:

```go
jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()})
```

Любой токен с алгоритмом, отличным от `HS256` (включая `none` и попытку
подмены на `RS256` с публичным ключом как HMAC-секретом), отклоняется до
того, как дело дойдёт до проверки подписи.

### 2. Отсутствие проверки срока действия (`exp`)

**Проблема (`vuln`):** валидация claims отключена целиком:

```go
jwt.WithoutClaimsValidation()
```

Это выключает встроенную сверку `exp`/`nbf` с текущим временем. Токен,
просроченный хоть на год, продолжает считаться валидным.

**Фикс (`fixed`):** опция `WithoutClaimsValidation()` убрана — встроенная
проверка `exp` в v5 включена по умолчанию, и дополнительно:

```go
jwt.WithExpirationRequired()
```

Это требует, чтобы поле `exp` обязательно присутствовало (иначе «вечный»
токен без `exp` тоже считался бы валидным). При истёкшем `exp` парсер
возвращает `jwt.ErrTokenExpired`.

### 3. Отсутствие проверки издателя (`iss`)

**Проблема (`vuln`):** поле `iss` кладётся в токен при выдаче, но при
проверке никогда не сравнивается с ожидаемым значением — токен,
подписанный тем же секретом, но с произвольным `iss`, проходит.

**Фикс (`fixed`):**

```go
jwt.WithIssuer(tokenIssuer) // tokenIssuer = "jwtlab-auth"
```

Парсер сам достаёт `iss` из claims и сравнивает со строкой, которую ожидает
сервис. Несовпадение → `jwt.ErrTokenInvalidIssuer`.

### 4. Отсутствие проверки аудитории (`aud`)

**Проблема (`vuln`):** то же самое с `aud` — токен, выданный «для одного
сервиса», можно переиспользовать для другого, если оба проверяют подпись
одним и тем же ключом.

**Фикс (`fixed`):**

```go
jwt.WithAudience(tokenAudience) // tokenAudience = "jwtlab-api"
```

Токен с любым `aud`, кроме ожидаемого, отклоняется с
`jwt.ErrTokenInvalidAudience`.

### Итоговый вызов валидатора в `fixed/main.go`

Все четыре фикса собраны в одном месте:

```go
_, err := jwt.ParseWithClaims(tokenStr, claims,
    func(t *jwt.Token) (any, error) { return jwtSecret, nil },
    jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}), // (1) алгоритм
    jwt.WithExpirationRequired(),                                  // (2) exp
    jwt.WithIssuer(tokenIssuer),                                   // (3) iss
    jwt.WithAudience(tokenAudience),                                // (4) aud
    jwt.WithLeeway(30*time.Second),                                 // допуск на рассинхрон часов
)
```

И соответствующая обработка ошибок в хендлере, чтобы не путать причины
отказа между собой:

```go
switch {
case errors.Is(err, jwt.ErrTokenExpired):
    http.Error(w, "token expired", http.StatusUnauthorized)
case errors.Is(err, jwt.ErrTokenInvalidIssuer):
    http.Error(w, "invalid issuer", http.StatusUnauthorized)
case errors.Is(err, jwt.ErrTokenInvalidAudience):
    http.Error(w, "invalid audience", http.StatusUnauthorized)
case errors.Is(err, jwt.ErrTokenSignatureInvalid):
    http.Error(w, "invalid signature", http.StatusUnauthorized)
default:
    http.Error(w, "invalid token", http.StatusUnauthorized)
}
```

## Структура проекта

```
jwt-task/
├── README.md
├── vuln/
│   ├── main.go      # без проверок алгоритма/exp/iss/aud
│   ├── go.mod
│   └── test.sh       # все атаки должны ПРОХОДИТЬ
└── fixed/
    ├── main.go       # с WithValidMethods/WithExpirationRequired/WithIssuer/WithAudience
    ├── go.mod
    └── test.sh       # все атаки должны ОТКЛОНЯТЬСЯ
```