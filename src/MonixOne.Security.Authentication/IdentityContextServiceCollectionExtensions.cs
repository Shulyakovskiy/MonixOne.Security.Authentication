using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace MonixOne.Security.Authentication;

/// <summary>
/// Регистрирует доступ к данным пользователя текущего HTTP-запроса.
/// </summary>
public static class IdentityContextServiceCollectionExtensions
{
    /// <summary>
    /// Регистрирует <see cref="IdentityContext"/> и его контракт <see cref="IIdentityContext"/> как scoped-сервисы.
    /// </summary>
    public static IServiceCollection AddIdentityContext(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);

        services.AddHttpContextAccessor();
        services.TryAddScoped<IdentityContext>();
        services.TryAddScoped<IIdentityContext>(
            static serviceProvider => serviceProvider.GetRequiredService<IdentityContext>());

        return services;
    }
}
