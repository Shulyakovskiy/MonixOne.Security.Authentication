namespace MonixOne.Security.Authentication;

/// <summary>
/// Предоставляет данные аутентифицированного пользователя в текущем HTTP-запросе.
/// </summary>
public interface IIdentityContext
{
    /// <summary>
    /// Возвращает значение claim <c>sub</c> или <see langword="null"/>, если текущий запрос не аутентифицирован.
    /// </summary>
    string? UserId { get; }

    /// <summary>
    /// Перечисляет уникальные значения claims <c>role</c> или не возвращает значений, если текущий запрос не аутентифицирован.
    /// </summary>
    IEnumerable<string> GetRoles();

    /// <summary>
    /// Перечисляет уникальные OAuth scopes из claims <c>scope</c> или не возвращает значений, если текущий запрос не аутентифицирован.
    /// </summary>
    IEnumerable<string> GetScopes();
}
