using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using Shouldly;
using Xunit;

namespace MonixOne.Security.Authentication.Tests;

public sealed class PlatformAuthenticationServiceCollectionExtensionsTests
{
    private const string Authority = "https://identity.example.test";
    private const string Audience = "example-api";

    /// <summary>
    /// Проверяет строгую настройку JWT Bearer validation из секции Identity.
    /// </summary>
    [Fact]
    public void AddPlatformAuthentication_ValidConfiguration_ConfiguresJwtBearerValidation()
    {
        // Arrange
        var configuration = CreateConfiguration();
        var services = new ServiceCollection();
        services.AddLogging();

        // Act
        services.AddPlatformAuthentication(configuration, new TestHostEnvironment("Production"));
        using var provider = services.BuildServiceProvider();
        var options = provider
            .GetRequiredService<IOptionsMonitor<JwtBearerOptions>>()
            .Get(JwtBearerDefaults.AuthenticationScheme);

        // Assert
        options.Authority.ShouldBe(Authority);
        options.Audience.ShouldBe(Audience);
        options.RequireHttpsMetadata.ShouldBeTrue();
        options.MapInboundClaims.ShouldBeFalse();
        options.TokenValidationParameters.RequireExpirationTime.ShouldBeTrue();
        options.TokenValidationParameters.RequireSignedTokens.ShouldBeTrue();
        options.TokenValidationParameters.ValidateIssuer.ShouldBeTrue();
        options.TokenValidationParameters.ValidateAudience.ShouldBeTrue();
        options.TokenValidationParameters.ValidateIssuerSigningKey.ShouldBeTrue();
        options.TokenValidationParameters.ValidateLifetime.ShouldBeTrue();
        options.TokenValidationParameters.ValidTypes.ShouldContain(OAuthTokenDefaults.AccessTokenType);
    }

    /// <summary>
    /// Проверяет запрет HTTP discovery/JWKS за пределами окружения Local.
    /// </summary>
    [Fact]
    public void AddPlatformAuthentication_HttpAuthorityInProduction_ThrowsValidationException()
    {
        // Arrange
        var configuration = CreateConfiguration(
            authority: "http://identity.example.test",
            requireHttpsMetadata: false);
        var services = new ServiceCollection();

        // Act
        var exception = Should.Throw<OptionsValidationException>(() =>
            services.AddPlatformAuthentication(configuration, new TestHostEnvironment("Production")));

        // Assert
        exception.Failures.ShouldContain(
            "Параметр 'Identity:RequireHttpsMetadata' можно отключать только в окружении Local.");
    }

    /// <summary>
    /// Проверяет разрешение HTTP metadata только для локального контура разработки.
    /// </summary>
    [Fact]
    public void AddPlatformAuthentication_HttpAuthorityInLocal_ConfiguresJwtBearer()
    {
        // Arrange
        var configuration = CreateConfiguration(
            authority: "http://localhost:8000",
            requireHttpsMetadata: false);
        var services = new ServiceCollection();
        services.AddLogging();

        // Act
        services.AddPlatformAuthentication(configuration, new TestHostEnvironment("Local"));
        using var provider = services.BuildServiceProvider();
        var options = provider
            .GetRequiredService<IOptionsMonitor<JwtBearerOptions>>()
            .Get(JwtBearerDefaults.AuthenticationScheme);

        // Assert
        options.RequireHttpsMetadata.ShouldBeFalse();
        options.Authority.ShouldBe("http://localhost:8000");
    }

    /// <summary>
    /// Проверяет автоматическую регистрацию контекста пользователя вместе с JWT validation.
    /// </summary>
    [Fact]
    public void AddPlatformAuthentication_RegistersIdentityContextContract()
    {
        // Arrange
        var configuration = CreateConfiguration();
        var services = new ServiceCollection();

        // Act
        services.AddPlatformAuthentication(configuration, new TestHostEnvironment("Production"));
        using var provider = services.BuildServiceProvider();
        using var scope = provider.CreateScope();

        // Assert
        var contract = scope.ServiceProvider.GetRequiredService<IIdentityContext>();
        var implementation = scope.ServiceProvider.GetRequiredService<IdentityContext>();

        contract.ShouldBeSameAs(implementation);
    }

    /// <summary>
    /// Проверяет ограничение максимального clock skew пятью минутами.
    /// </summary>
    [Theory]
    [InlineData(-1)]
    [InlineData(301)]
    public void AddPlatformAuthentication_InvalidClockSkew_ThrowsValidationException(int clockSkewSeconds)
    {
        // Arrange
        var configuration = CreateConfiguration(clockSkewSeconds: clockSkewSeconds);
        var services = new ServiceCollection();

        // Act
        var exception = Should.Throw<OptionsValidationException>(() =>
            services.AddPlatformAuthentication(configuration, new TestHostEnvironment("Production")));

        // Assert
        exception.Failures.ShouldContain(failure => failure.Contains("Identity:ClockSkewSeconds", StringComparison.Ordinal));
    }

    private static IConfiguration CreateConfiguration(
        string authority = Authority,
        bool requireHttpsMetadata = true,
        int clockSkewSeconds = 30) =>
        new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                [$"{PlatformAuthenticationOptions.SectionName}:Authority"] = authority,
                [$"{PlatformAuthenticationOptions.SectionName}:Audience"] = Audience,
                [$"{PlatformAuthenticationOptions.SectionName}:RequireHttpsMetadata"] =
                    requireHttpsMetadata.ToString(),
                [$"{PlatformAuthenticationOptions.SectionName}:ClockSkewSeconds"] =
                    clockSkewSeconds.ToString(System.Globalization.CultureInfo.InvariantCulture)
            })
            .Build();

    private sealed class TestHostEnvironment(string environmentName) : IHostEnvironment
    {
        public string EnvironmentName { get; set; } = environmentName;
        public string ApplicationName { get; set; } = nameof(MonixOne.Security.Authentication.Tests);
        public string ContentRootPath { get; set; } = AppContext.BaseDirectory;
        public IFileProvider ContentRootFileProvider { get; set; } = new NullFileProvider();
    }
}
