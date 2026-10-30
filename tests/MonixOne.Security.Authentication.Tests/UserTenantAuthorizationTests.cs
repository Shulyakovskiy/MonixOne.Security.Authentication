using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Shouldly;
using Xunit;

namespace MonixOne.Security.Authentication.Tests;

public sealed class UserTenantAuthorizationTests
{
    private const string Scope = "resource.read";

    [Theory]
    [InlineData("mbr", null, true)]
    [InlineData("lkb", null, true)]
    [InlineData(null, null, false)]
    [InlineData("", null, false)]
    [InlineData(" ", null, false)]
    [InlineData("unknown", null, false)]
    [InlineData("MBR", null, false)]
    [InlineData("mbr", "mbr", false)]
    [InlineData("mbr", "lkb", false)]
    public async Task UserToken_RequiresSingleConfiguredTenant(
        string? tenant,
        string? secondTenant,
        bool expected
    )
    {
        // Arrange
        await using var provider = CreateProvider("mbr", "lkb");
        var claims = UserClaims();
        if (tenant is not null)
            claims.Add(new Claim("tenant_id", tenant));
        if (secondTenant is not null)
            claims.Add(new Claim("tenant_id", secondTenant));
        var principal = new ClaimsPrincipal(new ClaimsIdentity(claims, "Test"));

        // Act
        var result = await provider
            .GetRequiredService<IAuthorizationService>()
            .AuthorizeAsync(principal, resource: null, OAuthAuthorizationPolicies.ForScope(Scope));

        // Assert
        result.Succeeded.ShouldBe(expected);
    }

    [Theory]
    [InlineData("customer-a", "customer-a", true)]
    [InlineData("customer-a", "mbr", false)]
    [InlineData("mbr", "lkb", false)]
    public async Task TenantAuthorization_UsesConfiguredAllowList(
        string configuredTenant,
        string tokenTenant,
        bool expected
    )
    {
        // Arrange
        await using var provider = CreateProvider(configuredTenant);
        var claims = UserClaims();
        claims.Add(new Claim("tenant_id", tokenTenant));
        var principal = new ClaimsPrincipal(new ClaimsIdentity(claims, "Test"));

        // Act
        var result = await provider
            .GetRequiredService<IAuthorizationService>()
            .AuthorizeAsync(principal, resource: null, OAuthAuthorizationPolicies.ForScope(Scope));

        // Assert
        result.Succeeded.ShouldBe(expected);
    }

    [Theory]
    [InlineData("django")]
    [InlineData("location-service")]
    public async Task ServiceToken_WithoutTenant_KeepsScopeAccess(string clientId)
    {
        // Arrange
        await using var provider = CreateProvider("customer-a");
        var principal = new ClaimsPrincipal(
            new ClaimsIdentity(
                [
                    new Claim("sub", clientId),
                    new Claim("client_id", clientId),
                    new Claim("scope", Scope),
                ],
                "Test"
            )
        );

        // Act
        var result = await provider
            .GetRequiredService<IAuthorizationService>()
            .AuthorizeAsync(principal, resource: null, OAuthAuthorizationPolicies.ForScope(Scope));

        // Assert
        result.Succeeded.ShouldBeTrue();
    }

    [Theory]
    [InlineData("django", null)]
    [InlineData("django", "mobile-app")]
    [InlineData("", "")]
    public async Task WithoutTenant_RequiresUnambiguousServiceIdentity(
        string subject,
        string? clientId
    )
    {
        // Arrange
        await using var provider = CreateProvider("mbr");
        var claims = new List<Claim> { new("sub", subject), new("scope", Scope) };
        if (clientId is not null)
            claims.Add(new Claim("client_id", clientId));
        var principal = new ClaimsPrincipal(new ClaimsIdentity(claims, "Test"));

        // Act
        var result = await provider
            .GetRequiredService<IAuthorizationService>()
            .AuthorizeAsync(principal, resource: null, OAuthAuthorizationPolicies.ForScope(Scope));

        // Assert
        result.Succeeded.ShouldBeFalse();
    }

    [Theory]
    [InlineData("sub")]
    [InlineData("client_id")]
    public async Task RepeatedServiceClaim_DoesNotBypassTenantCheck(string repeatedClaim)
    {
        // Arrange
        await using var provider = CreateProvider("mbr");
        var principal = new ClaimsPrincipal(
            new ClaimsIdentity(
                [
                    new Claim("sub", "django"),
                    new Claim("client_id", "django"),
                    new Claim(repeatedClaim, "django"),
                    new Claim("scope", Scope),
                ],
                "Test"
            )
        );

        // Act
        var result = await provider
            .GetRequiredService<IAuthorizationService>()
            .AuthorizeAsync(principal, resource: null, OAuthAuthorizationPolicies.ForScope(Scope));

        // Assert
        result.Succeeded.ShouldBeFalse();
    }

    [Theory]
    [InlineData("user-1", "mobile-app")]
    [InlineData("django", "django")]
    public async Task WithoutRequiredScope_TenantHandlerDoesNotGrantAccess(
        string subject,
        string clientId
    )
    {
        // Arrange
        await using var provider = CreateProvider("mbr");
        var principal = new ClaimsPrincipal(
            new ClaimsIdentity(
                [
                    new Claim("sub", subject),
                    new Claim("client_id", clientId),
                    new Claim("tenant_id", "mbr"),
                    new Claim("scope", "resource.write"),
                ],
                "Test"
            )
        );

        // Act
        var result = await provider
            .GetRequiredService<IAuthorizationService>()
            .AuthorizeAsync(principal, resource: null, OAuthAuthorizationPolicies.ForScope(Scope));

        // Assert
        result.Succeeded.ShouldBeFalse();
    }

    [Theory]
    [InlineData(false, true)]
    [InlineData(true, false)]
    public async Task PermissivePolicy_ChecksTenantOnlyForAuthenticatedUser(
        bool authenticated,
        bool expected
    )
    {
        // Arrange — чужая policy не может отменить Fail, а аноним не получает tenant-требование.
        await using var provider = CreateProvider("mbr");
        var principal = new ClaimsPrincipal(
            new ClaimsIdentity(UserClaims(), authenticated ? "Test" : null)
        );

        // Act
        var result = await provider
            .GetRequiredService<IAuthorizationService>()
            .AuthorizeAsync(principal, resource: null, "permissive");

        // Assert
        result.Succeeded.ShouldBe(expected);
    }

    [Fact]
    public async Task UnauthenticatedIdentity_CannotSupplyTenantOrServiceExemption()
    {
        // Arrange
        await using var provider = CreateProvider("mbr");
        var principal = new ClaimsPrincipal([
            new ClaimsIdentity(UserClaims(), "Test"),
            new ClaimsIdentity([
                new Claim("tenant_id", "mbr"),
                new Claim("sub", "django"),
                new Claim("client_id", "django"),
            ]),
        ]);

        // Act
        var result = await provider
            .GetRequiredService<IAuthorizationService>()
            .AuthorizeAsync(principal, resource: null, OAuthAuthorizationPolicies.ForScope(Scope));

        // Assert
        result.Succeeded.ShouldBeFalse();
    }

    [Theory]
    [InlineData("TENANT_ID")]
    [InlineData("Tenant_Id")]
    public async Task TenantClaimType_IsCaseSensitive(string claimType)
    {
        // Arrange
        await using var provider = CreateProvider("mbr");
        var claims = UserClaims();
        claims.Add(new Claim(claimType, "mbr"));
        var principal = new ClaimsPrincipal(new ClaimsIdentity(claims, "Test"));

        // Act
        var result = await provider
            .GetRequiredService<IAuthorizationService>()
            .AuthorizeAsync(principal, resource: null, OAuthAuthorizationPolicies.ForScope(Scope));

        // Assert
        result.Succeeded.ShouldBeFalse();
    }

    public static TheoryData<string[]> InvalidAllowLists =>
        new()
        {
            Array.Empty<string>(),
            new[] { "" },
            new[] { " " },
            new[] { "mbr", "mbr" },
            new[] { "mbr", "" },
        };

    [Theory]
    [MemberData(nameof(InvalidAllowLists))]
    public void InvalidAllowList_FailsStartupValidation(string[] tenants)
    {
        // Arrange
        using var provider = CreateProvider(tenants);

        // Act
        var exception = Should.Throw<OptionsValidationException>(() =>
            provider.GetRequiredService<IStartupValidator>().Validate()
        );

        // Assert
        exception.Failures.ShouldContain(failure =>
            failure.Contains("Identity:AllowedUserTenants", StringComparison.Ordinal)
        );
    }

    [Fact]
    public void ValidAllowList_PassesStartupValidation()
    {
        // Arrange
        using var provider = CreateProvider("customer-a", "customer-b");

        // Act / Assert
        Should.NotThrow(() => provider.GetRequiredService<IStartupValidator>().Validate());
    }

    private static List<Claim> UserClaims() =>
        [new("sub", "user-1"), new("client_id", "mobile-app"), new("scope", Scope)];

    private static ServiceProvider CreateProvider(params string[] tenants)
    {
        var values = tenants.Select(
            (tenant, index) =>
                new KeyValuePair<string, string?>($"Identity:AllowedUserTenants:{index}", tenant)
        );
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(values).Build();
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSingleton<IConfiguration>(configuration);
        services.AddUserTenantAuthorization();
        services.AddAuthorization(options =>
        {
            options.AddScopePolicy(Scope);
            options.AddPolicy("permissive", policy => policy.RequireAssertion(_ => true));
        });
        return services.BuildServiceProvider();
    }
}
