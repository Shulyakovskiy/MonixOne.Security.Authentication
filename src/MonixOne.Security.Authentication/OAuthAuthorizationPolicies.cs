using Microsoft.AspNetCore.Authorization;

namespace MonixOne.Security.Authentication;

/// <summary>
/// Формирует единообразные authorization policies для OAuth scopes.
/// </summary>
public static class OAuthAuthorizationPolicies
{
    private const string ScopePolicyPrefix = "oauth.scope:";

    /// <summary>
    /// Возвращает имя policy, требующей указанный OAuth scope.
    /// </summary>
    public static string ForScope(string scope)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(scope);
        return ScopePolicyPrefix + scope;
    }

    /// <summary>
    /// Регистрирует именованную policy для точной проверки указанного OAuth scope.
    /// </summary>
    public static void AddScopePolicy(this AuthorizationOptions options, string scope)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentException.ThrowIfNullOrWhiteSpace(scope);

        options.AddPolicy(
            ForScope(scope),
            policy => policy.RequireScope(scope));
    }

    /// <summary>
    /// Требует аутентифицированный access token с указанным OAuth scope.
    /// </summary>
    public static AuthorizationPolicyBuilder RequireScope(
        this AuthorizationPolicyBuilder policy,
        string scope)
    {
        ArgumentNullException.ThrowIfNull(policy);
        ArgumentException.ThrowIfNullOrWhiteSpace(scope);

        return policy
            .RequireAuthenticatedUser()
            .RequireAssertion(context => context.User.HasScope(scope));
    }
}
