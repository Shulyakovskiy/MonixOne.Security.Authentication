using System.Security.Claims;

namespace MonixOne.Security.Authentication;

/// <summary>
/// Предоставляет точные проверки OAuth claims для domain authorization Resource Server.
/// </summary>
public static class ClaimsPrincipalExtensions
{
    /// <summary>
    /// Проверяет наличие scope с учётом одиночных, повторяющихся и разделённых пробелами claims.
    /// </summary>
    public static bool HasScope(this ClaimsPrincipal principal, string requiredScope)
    {
        ArgumentNullException.ThrowIfNull(principal);
        ArgumentException.ThrowIfNullOrWhiteSpace(requiredScope);

        return principal
            .FindAll(OAuthTokenDefaults.ScopeClaim)
            .SelectMany(claim => claim.Value.Split(' ', StringSplitOptions.RemoveEmptyEntries))
            .Contains(requiredScope, StringComparer.Ordinal);
    }
}
