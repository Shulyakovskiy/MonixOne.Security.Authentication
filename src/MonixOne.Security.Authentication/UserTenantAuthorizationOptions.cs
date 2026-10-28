namespace MonixOne.Security.Authentication;

/// <summary>
/// Настройки tenant-авторизации пользователей из секции <c>Identity</c>.
/// </summary>
public sealed class UserTenantAuthorizationOptions
{
    /// <summary>
    /// Разрешённые значения claim <c>tenant_id</c> с учётом регистра.
    /// При включении tenant-авторизации список должен быть непустым
    /// и не содержать пустых или повторных значений.
    /// </summary>
    public string[] AllowedUserTenants { get; init; } = [];
}
