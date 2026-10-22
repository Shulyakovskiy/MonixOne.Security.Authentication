# MonixOne.Security.Authentication

Reusable JWT Bearer authentication и OAuth scope authorization для ASP.NET Core Resource Servers на .NET 10.

Библиотека проверяет:

- подпись JWT по discovery/JWKS;
- точный `issuer`;
- точный `audience`;
- обязательный `exp` и временные границы `nbf`/`exp`;
- JOSE type `at+jwt`;
- требуемый OAuth scope.

Она не выпускает tokens и не заменяет domain authorization конечного сервиса. Опциональное
расширение `AddServiceClients` регистрирует исходящие HTTP-контракты и при необходимости
получает client credentials tokens.

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
    var isAuthenticated = identity.IsAuthenticated;
    var userId = identity.UserId;
    var roles = identity.GetRoles();
    var scopes = identity.GetScopes();

    return Results.Ok(new { isAuthenticated, userId, roles, scopes });
}).RequireAuthorization();
```

`IsAuthenticated` отражает `HttpContext.User.Identity.IsAuthenticated` и не зависит от наличия claim `sub`. `UserId` — точное непустое значение claim `sub`, поэтому библиотека не предполагает, что идентификатор обязательно имеет формат `Guid`. `GetRoles()` перечисляет повторяющиеся claims `role`, а `GetScopes()` — повторяющиеся или разделённые пробелами claims `scope`; значения в каждой последовательности уникальны и не копируются при вызове метода.

Если access token отсутствует, не прошёл authentication или код выполняется вне HTTP-запроса, `IsAuthenticated` равен `false`, `UserId` и `ExternalUserId` равны `null`, а `GetRoles()` и `GetScopes()` возвращают пустую последовательность. Это не заменяет endpoint authorization: доступ по ролям и scopes по-прежнему должен защищаться policy либо доменной проверкой.

Если сервис настраивает authentication самостоятельно и не вызывает `AddPlatformAuthentication`, зарегистрируйте reader отдельно:

```csharp
builder.Services.AddIdentityContext();
```

## Service-to-service HTTP-клиенты

`AddServiceClients` связывает Refit-контракты с настройками из `appsettings`. Режим
`Authentication` задаётся отдельно для каждой группы:

| Authentication | Поведение | Обязательные настройки |
| --- | --- | --- |
| `ClientCredentials` (по умолчанию) | Получает и кэширует access token, добавляет `Authorization: Bearer ...` | `Identity:Authority`, `Identity:ClientId`, `Identity:ClientSecret` и непустые `Scopes` |
| `None` | Не подключает token handler и не обращается к Identity | `Identity` и `Scopes` не требуются; `Scopes` игнорируются |

В первом аргументе передаётся секция, содержащая `ServiceClients` (например,
`Infrastructure`), во втором — секция `Identity`. Если регистрируются только группы
`None`, вторым аргументом можно передать `null` или `GetSection("Identity")`, даже когда
секции `Identity` нет. Для существующих конфигураций без `Authentication` сохраняется
`ClientCredentials`. Неизвестные значения режима приводят к ошибке регистрации.

Если `ServiceClients` отсутствует или `Services` пуст, метод ничего не регистрирует — в том
числе не требует `Identity:Authority`, `Identity:ClientId` и `Identity:ClientSecret`. Контракт,
чья группа отсутствует в `Services`, также пропускается. Это позволяет одному образу включать
клиенты только в нужных окружениях.

```json
{
  "Infrastructure": {
    "ServiceClients": {
      "Services": [
        {
          "Group": "profile",
          "BaseAddress": "https://profile.internal",
          "Authentication": "ClientCredentials",
          "Scopes": ["profile-service.intra_read"]
        },
        {
          "Group": "postgrest",
          "BaseAddress": "http://postgrest:3000",
          "Authentication": "None"
        }
      ]
    }
  },
  "Identity": {
    "Authority": "https://identity.internal",
    "ClientId": "location-service",
    "ClientSecret": "stored-outside-appsettings"
  }
}
```

Контракты принадлежат приложению, поэтому оно явно сопоставляет их с группами:

```csharp
builder.Services.AddServiceClients(
    builder.Configuration.GetRequiredSection("Infrastructure"),
    builder.Configuration.GetRequiredSection("Identity"),
    registrar =>
    {
        // Регистрация контракта
        registrar.Add<IProfileService>(ProfileServiceGroup.Name);
        registrar.Add<IPostgRestService>("postgrest");
    });
```

Для каждого сервиса обязательны абсолютный HTTP(S) `BaseAddress` и уникальный `Group`.
Хотя бы один непустой `Scope` обязателен только для `ClientCredentials`. Если `Resilience`
не задан, для обоих режимов применяется стандартный resilience pipeline .NET; его можно
настроить в `ServiceClients:Resilience`. Повторные попытки для небезопасных HTTP-методов
отключены.

### PostgREST без токена

Если нужен только анонимный PostgREST, достаточно следующего `appsettings.json` без
секции `Identity` и без `Scopes`:

```json
{
  "Infrastructure": {
    "ServiceClients": {
      "Services": [
        {
          "Group": "postgrest",
          "BaseAddress": "http://postgrest:3000",
          "Authentication": "None"
        }
      ]
    }
  }
}
```

Зарегистрируйте прикладной Refit-контракт:

```csharp
using MonixOne.Security.Authentication;
using Refit;

builder.Services.AddServiceClients(
    builder.Configuration.GetRequiredSection("Infrastructure"),
    identityConfiguration: null,
    registerContracts: registrar => registrar.Add<IPostgRestService>("postgrest"));

public interface IPostgRestService
{
    [Get("/locations")]
    Task<LocationResponse[]> GetLocations(
        [AliasAs("select")] string select,
        CancellationToken ct);
}

public sealed record LocationResponse(int Id, string Name);
```

Вызов `GetLocations("id,name", ct)` выполнит `GET /locations?select=id%2Cname` без
автоматического добавления `Authorization`. Настройка `None` управляет только исходящим
клиентом. В самом PostgREST должна быть задана `db-anon-role` (например, через
`PGRST_DB_ANON_ROLE=web_anon`), а эта роль должна иметь права на используемую схему и
чтение `locations`; роль подключения PostgREST должна иметь право переключаться в неё.
Подробнее — в [документации PostgREST](https://docs.postgrest.org/en/v14/references/auth.html).

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
