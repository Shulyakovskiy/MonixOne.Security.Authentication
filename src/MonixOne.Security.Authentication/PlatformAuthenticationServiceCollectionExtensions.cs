using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace MonixOne.Security.Authentication;

/// <summary>
/// Регистрирует стандартную проверку access token для ASP.NET Core Resource Servers.
/// </summary>
public static class PlatformAuthenticationServiceCollectionExtensions
{
    private const int MaximumClockSkewSeconds = 300;

    /// <summary>
    /// Регистрирует JWT Bearer validation из секции <c>Identity</c>.
    /// </summary>
    public static IServiceCollection AddPlatformAuthentication(
        this IServiceCollection services,
        IConfiguration configuration,
        IHostEnvironment environment)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configuration);
        ArgumentNullException.ThrowIfNull(environment);

        var options = configuration
            .GetSection(PlatformAuthenticationOptions.SectionName)
            .Get<PlatformAuthenticationOptions>() ?? new PlatformAuthenticationOptions();
        ValidateOrThrow(options, environment);

        services.AddSingleton(Options.Create(options));
        services
            .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
            .AddJwtBearer(jwtBearerOptions =>
            {
                jwtBearerOptions.Authority = options.Authority;
                jwtBearerOptions.Audience = options.Audience;
                jwtBearerOptions.RequireHttpsMetadata = options.RequireHttpsMetadata;
                jwtBearerOptions.MapInboundClaims = false;
                jwtBearerOptions.IncludeErrorDetails = false;
                jwtBearerOptions.SaveToken = false;
                jwtBearerOptions.RefreshOnIssuerKeyNotFound = true;
                jwtBearerOptions.TokenValidationParameters = new TokenValidationParameters
                {
                    ClockSkew = TimeSpan.FromSeconds(options.ClockSkewSeconds),
                    RequireExpirationTime = true,
                    RequireSignedTokens = true,
                    ValidateAudience = true,
                    ValidateIssuer = true,
                    ValidateIssuerSigningKey = true,
                    ValidateLifetime = true,
                    ValidAudience = options.Audience,
                    ValidTypes = [OAuthTokenDefaults.AccessTokenType]
                };
            });

        return services;
    }

    private static void ValidateOrThrow(
        PlatformAuthenticationOptions options,
        IHostEnvironment environment)
    {
        var failures = new List<string>();
        var authorityIsValid = Uri.TryCreate(options.Authority, UriKind.Absolute, out var authority)
                               && (authority.Scheme == Uri.UriSchemeHttps
                                   || authority.Scheme == Uri.UriSchemeHttp)
                               && !string.IsNullOrWhiteSpace(authority.Host)
                               && string.IsNullOrEmpty(authority.UserInfo)
                               && string.IsNullOrEmpty(authority.Query)
                               && string.IsNullOrEmpty(authority.Fragment);
        if (!authorityIsValid)
        {
            failures.Add(
                "Параметр 'Identity:Authority' должен быть абсолютным HTTP/HTTPS URL без user info, query-параметров и fragment.");
        }
        else if (options.RequireHttpsMetadata && authority!.Scheme != Uri.UriSchemeHttps)
        {
            failures.Add(
                "Параметр 'Identity:Authority' должен использовать HTTPS, когда 'Identity:RequireHttpsMetadata' включён.");
        }

        if (!options.RequireHttpsMetadata && !environment.IsEnvironment("Local"))
        {
            failures.Add(
                "Параметр 'Identity:RequireHttpsMetadata' можно отключать только в окружении Local.");
        }

        if (string.IsNullOrWhiteSpace(options.Audience))
            failures.Add("Параметр 'Identity:Audience' обязателен.");

        if (options.ClockSkewSeconds is < 0 or > MaximumClockSkewSeconds)
        {
            failures.Add(
                $"Параметр 'Identity:ClockSkewSeconds' должен быть в диапазоне от 0 до {MaximumClockSkewSeconds} секунд.");
        }

        if (failures.Count != 0)
        {
            throw new OptionsValidationException(
                PlatformAuthenticationOptions.SectionName,
                typeof(PlatformAuthenticationOptions),
                failures);
        }
    }
}
