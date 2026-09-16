# MonixOne.Security.Authentication

Reusable JWT Bearer authentication и OAuth scope authorization для ASP.NET Core Resource Servers на .NET 10.

Библиотека проверяет:

- подпись JWT по discovery/JWKS;
- точный `issuer`;
- точный `audience`;
- обязательный `exp` и временные границы `nbf`/`exp`;
- JOSE type `at+jwt`;
- требуемый OAuth scope.

Она не выпускает tokens, не получает client credentials tokens и не заменяет domain authorization конечного сервиса.

## Подключение

```bash
dotnet add package MonixOne.Security.Authentication
```

Добавьте настройки Resource Server:

```json
{
  "Identity": {
    "Authority": "https://identity.example.com",
    "Audience": "beetroute-api",
    "RequireHttpsMetadata": true,
    "ClockSkewSeconds": 30
  }
}
```

`ClockSkewSeconds` задаётся в секундах и должен находиться в диапазоне `0..300`. Отключение `RequireHttpsMetadata` разрешено только в окружении `Local`.

Зарегистрируйте authentication и необходимые сервису scope policies:

```csharp
using MonixOne.Security.Authentication;

builder.Services.AddPlatformAuthentication(
    builder.Configuration,
    builder.Environment);

builder.Services.AddAuthorization(options =>
{
    options.AddScopePolicy("location.read");
    options.AddScopePolicy("location.write");
});
```

Названия scopes должны приходить из contracts конечной системы, а не из этой библиотеки.

Добавьте middleware в правильном порядке:

```csharp
app.UseAuthentication();
app.UseAuthorization();
```

Защитите endpoint точным scope:

```csharp
app.MapGet("/api/v1/locations", Handle)
    .RequireAuthorization(
        OAuthAuthorizationPolicies.ForScope("location.read"));
```

Для FastEndpoints используйте то же имя policy:

```csharp
Policies(OAuthAuthorizationPolicies.ForScope("location.read"));
```

Health endpoints должны явно оставаться анонимными. Проверки владения ресурсом, ролей и других доменных правил выполняются после JWT/scope validation внутри конечного сервиса.

## Данные пользователя в обработчиках

`AddPlatformAuthentication` автоматически регистрирует scoped `IdentityContext` и его контракт `IIdentityContext`. В endpoint, handler или application service зависите от контракта:

```csharp
using MonixOne.Security.Authentication;

app.MapGet("/api/v1/profile", (IIdentityContext identity) =>
{
    var userId = identity.UserId;
    var roles = identity.GetRoles();
    var scopes = identity.GetScopes();

    return Results.Ok(new { userId, roles, scopes });
}).RequireAuthorization();
```

`UserId` — точное непустое значение claim `sub`, поэтому библиотека не предполагает, что идентификатор обязательно имеет формат `Guid`. `GetRoles()` перечисляет повторяющиеся claims `role`, а `GetScopes()` — повторяющиеся или разделённые пробелами claims `scope`; значения в каждой последовательности уникальны и не копируются при вызове метода.

Если access token отсутствует, не прошёл authentication или код выполняется вне HTTP-запроса, `UserId` равен `null`, а `GetRoles()` и `GetScopes()` возвращают пустую последовательность. Это не заменяет endpoint authorization: доступ по ролям и scopes по-прежнему должен защищаться policy либо доменной проверкой.

Если сервис настраивает authentication самостоятельно и не вызывает `AddPlatformAuthentication`, зарегистрируйте reader отдельно:

```csharp
builder.Services.AddIdentityContext();
```

## Публикация

Версия пакета задаётся свойством `Version` в `MonixOne.Security.Authentication.csproj`.

Workflow `.github/workflows/publish.yml` запускается только после merge pull request в `main`, повторно выполняет restore/build/test/pack и получает временный NuGet API key через Trusted Publishing. Постоянный NuGet API key в GitHub secrets не используется.

Для Trusted Publishing должны совпадать:

```text
GitHub owner: Shulyakovskiy
Repository: MonixOne.Security.Authentication
Workflow: publish.yml
Environment: production
```

В GitHub Environment `production` требуется secret `NUGET_USER` с именем владельца NuGet.org. При повторной публикации существующей версии `--skip-duplicate` не создаёт новый пакет; перед релизом увеличьте `Version`.
