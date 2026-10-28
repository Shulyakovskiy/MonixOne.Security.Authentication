using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace MonixOne.Security.Authentication;

/// <summary>
/// Регистрирует общую tenant-проверку аутентифицированных пользователей при выполнении authorization policies.
/// </summary>
public static class UserTenantAuthorizationServiceCollectionExtensions
{
    /// <summary>
    /// Добавляет проверку tenant пользователя по массиву <c>Identity:AllowedUserTenants</c>.
    /// M2M principal с единственными непустыми claims <c>sub=client_id</c> не требует tenant.
    /// </summary>
    /// <remarks>
    /// Использует конфигурацию приложения из DI и проверяет настройки при старте.
    /// Не заменяет scope, role или endpoint authorization и не защищает <c>AllowAnonymous</c> endpoints.
    /// </remarks>
    public static IServiceCollection AddUserTenantAuthorization(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);

        services.AddOptions<UserTenantAuthorizationOptions>()
            .BindConfiguration(PlatformAuthenticationOptions.SectionName)
            .Validate(static options => options.AllowedUserTenants is { Length: > 0 } tenants
                                        && tenants.All(tenant => !string.IsNullOrWhiteSpace(tenant))
                                        && tenants.Distinct(StringComparer.Ordinal).Count() == tenants.Length,
                "Identity:AllowedUserTenants должен содержать непустой массив уникальных непустых tenant.")
            .ValidateOnStart();
        services.AddAuthorization();
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IAuthorizationHandler, UserTenantAuthorizationHandler>());

        return services;
    }
}
