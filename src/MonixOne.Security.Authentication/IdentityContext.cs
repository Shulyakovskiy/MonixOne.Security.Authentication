using Microsoft.AspNetCore.Http;

namespace MonixOne.Security.Authentication;

/// <summary>
/// Читает claims аутентифицированного пользователя из текущего HTTP-запроса.
/// </summary>
public sealed class IdentityContext : IIdentityContext
{
    private readonly IHttpContextAccessor _httpContextAccessor;

    /// <summary>
    /// Создаёт reader claims для текущего HTTP-запроса.
    /// </summary>
    public IdentityContext(IHttpContextAccessor httpContextAccessor)
    {
        ArgumentNullException.ThrowIfNull(httpContextAccessor);
        _httpContextAccessor = httpContextAccessor;
    }

    /// <inheritdoc />
    public string? UserId
    {
        get
        {
            var subject = GetAuthenticatedUser()?.FindFirst(OAuthTokenDefaults.SubjectClaim)?.Value;
            return string.IsNullOrWhiteSpace(subject) ? null : subject;
        }
    }

    /// <inheritdoc />
    public IEnumerable<string> GetRoles() => GetClaimValues(OAuthTokenDefaults.RoleClaim);

    /// <inheritdoc />
    public IEnumerable<string> GetScopes() => GetAuthenticatedUser() is { } user
        ? user
            .FindAll(OAuthTokenDefaults.ScopeClaim)
            .SelectMany(claim => claim.Value.Split(' ', StringSplitOptions.RemoveEmptyEntries))
            .Distinct(StringComparer.Ordinal)
        : Enumerable.Empty<string>();

    private IEnumerable<string> GetClaimValues(string claimType) =>
        GetAuthenticatedUser() is { } user
            ? user
                .FindAll(claimType)
                .Select(claim => claim.Value)
                .Where(value => !string.IsNullOrWhiteSpace(value))
                .Distinct(StringComparer.Ordinal)
            : Enumerable.Empty<string>();

    private System.Security.Claims.ClaimsPrincipal? GetAuthenticatedUser()
    {
        var user = _httpContextAccessor.HttpContext?.User;
        return user?.Identity?.IsAuthenticated is true ? user : null;
    }
}
