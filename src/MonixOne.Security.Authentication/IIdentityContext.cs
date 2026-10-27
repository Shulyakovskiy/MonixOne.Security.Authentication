namespace MonixOne.Security.Authentication;

/// <summary>
/// Предоставляет данные аутентифицированного пользователя в текущем HTTP-запросе.
/// </summary>
public interface IIdentityContext
{
    /// <summary>
    /// Возвращает <see langword="true"/>, если пользователь текущего HTTP-запроса аутентифицирован.
    /// Вне HTTP-запроса возвращает <see langword="false"/>.
    /// </summary>
    bool IsAuthenticated { get; }

    /// <summary>
    /// Возвращает значение claim <c>sub</c> или <see langword="null"/>, если текущий запрос не аутентифицирован.
    /// </summary>
    string? UserId { get; }

    /// <summary>
    /// Возвращает значение claim <c>sub-ext</c> или <see langword="null"/>, если текущий запрос не аутентифицирован.
    /// </summary>
    string? ExternalUserId { get; }

    /// <summary>
    /// Возвращает единственное непустое значение claim <c>tenant_id</c> аутентифицированного пользователя.
    /// Если claim отсутствует, повторяется или запрос не аутентифицирован, возвращает <see langword="null"/>.
    /// </summary>
    string? TenantId { get; }

    /// <summary>
    /// Перечисляет уникальные значения claims <c>role</c> или не возвращает значений, если текущий запрос не аутентифицирован.
    /// </summary>
    IEnumerable<string> GetRoles();

    /// <summary>
    /// Перечисляет уникальные OAuth scopes из claims <c>scope</c> или не возвращает значений, если текущий запрос не аутентифицирован.
    /// </summary>
    IEnumerable<string> GetScopes();
}
