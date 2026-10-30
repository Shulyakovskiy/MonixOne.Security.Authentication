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

        return GetSingleAuthenticatedClaim(principal, OAuthTokenDefaults.TenantIdClaim);
    }

    internal static bool IsServiceIdentity(this ClaimsPrincipal principal)
    {
        // Identity выпускает client_credentials с sub=client_id.
        // Отсутствия tenant для определения M2M недостаточно.
        var subject = GetSingleAuthenticatedClaim(principal, OAuthTokenDefaults.SubjectClaim);
        var clientId = GetSingleAuthenticatedClaim(principal, OAuthTokenDefaults.ClientIdClaim);
        return subject is not null && string.Equals(subject, clientId, StringComparison.Ordinal);
    }

    private static string? GetSingleAuthenticatedClaim(ClaimsPrincipal principal, string claimType)
    {
        string? value = null;
        foreach (
            var claim in principal
                .Identities.Where(identity => identity.IsAuthenticated)
                .SelectMany(identity => identity.Claims)
        )
        {
            if (!string.Equals(claim.Type, claimType, StringComparison.Ordinal))
                continue;

            if (value is not null || string.IsNullOrWhiteSpace(claim.Value))
                return null;

            value = claim.Value;
        }

        return value;
    }
}
