using Microsoft.AspNetCore.Authorization;

namespace MonixOne.Security.Authentication;

/// <summary>
/// Формирует единообразные authorization policies для OAuth scopes и tenant.
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

        options.AddPolicy(ForScope(scope), policy => policy.RequireScope(scope));
    }

    /// <summary>
    /// Требует аутентифицированный access token с указанным OAuth scope.
    /// </summary>
    public static AuthorizationPolicyBuilder RequireScope(
        this AuthorizationPolicyBuilder policy,
        string scope
    )
    {
        ArgumentNullException.ThrowIfNull(policy);
        ArgumentException.ThrowIfNullOrWhiteSpace(scope);

        return policy
            .RequireAuthenticatedUser()
            .RequireAssertion(context => context.User.HasScope(scope));
    }

    /// <summary>
    /// Требует аутентифицированного пользователя с единственным непустым claim <c>tenant_id</c>.
    /// Значение claim должно точно совпадать с указанным tenant с учётом регистра.
    /// </summary>
    public static AuthorizationPolicyBuilder RequireTenant(
        this AuthorizationPolicyBuilder policy,
        string tenantId
    )
    {
        ArgumentNullException.ThrowIfNull(policy);
        ArgumentException.ThrowIfNullOrWhiteSpace(tenantId);

        return policy
            .RequireAuthenticatedUser()
            .RequireAssertion(context =>
                string.Equals(context.User.GetTenantId(), tenantId, StringComparison.Ordinal)
            );
    }
}
