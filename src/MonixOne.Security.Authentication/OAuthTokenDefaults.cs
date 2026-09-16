namespace MonixOne.Security.Authentication;

/// <summary>
/// Содержит стандартные значения OAuth access token, используемые Resource Server.
/// </summary>
public static class OAuthTokenDefaults
{
    /// <summary>
    /// JOSE header <c>typ</c> для JWT access token согласно RFC 9068.
    /// </summary>
    public const string AccessTokenType = "at+jwt";

    /// <summary>
    /// Имя claim, содержащего выданные OAuth scopes.
    /// </summary>
    public const string ScopeClaim = "scope";

    /// <summary>
    /// Имя claim, содержащего неизменяемый идентификатор субъекта access token.
    /// </summary>
    public const string SubjectClaim = "sub";

    /// <summary>
    /// Имя claim, содержащего роль пользователя.
    /// </summary>
    public const string RoleClaim = "role";
}
