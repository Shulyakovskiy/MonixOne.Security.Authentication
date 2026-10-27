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

    internal static string? GetTenantId(this ClaimsPrincipal principal)
    {
        if (principal.Identity?.IsAuthenticated is not true)
            return null;

        string? tenantId = null;
        foreach (var claim in principal.Identities
                     .Where(identity => identity.IsAuthenticated)
                     .SelectMany(identity => identity.Claims))
        {
            if (!string.Equals(claim.Type, OAuthTokenDefaults.TenantIdClaim, StringComparison.Ordinal))
                continue;

            if (tenantId is not null || string.IsNullOrWhiteSpace(claim.Value))
                return null;

            tenantId = claim.Value;
        }

        return tenantId;
    }
}
