using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace MonixOne.Security.Authentication;

/// <summary>
/// Configures credentialed browser login requests from explicitly allowed origins.
/// </summary>
public static class BrowserLoginCorsExtensions
{
    private const string PolicyName = "BrowserLogin";

    /// <summary>
    /// Registers POST and Content-Type CORS permissions using Cors:Origins.
    /// An absent allowlist does not enable cross-origin access.
    /// </summary>
    public static IServiceCollection AddBrowserLoginCors(
        this IServiceCollection services,
        IConfiguration configuration
    )
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configuration);

        return services.AddCors(options =>
            options.AddPolicy(
                PolicyName,
                policy =>
                    policy
                        .WithOrigins(configuration.GetSection("Cors:Origins").Get<string[]>() ?? [])
                        .WithMethods("POST")
                        .WithHeaders("Content-Type")
                        .AllowCredentials()
            )
        );
    }

    /// <summary>
    /// Applies the browser login policy after routing and before authentication
    /// or tenant selection, so preflight does not require a browser session.
    /// </summary>
    public static IApplicationBuilder UseBrowserLoginCors(this IApplicationBuilder app)
    {
        ArgumentNullException.ThrowIfNull(app);
        return app.UseCors(PolicyName);
    }
}
