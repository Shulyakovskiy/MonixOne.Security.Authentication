using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.DependencyInjection;
using Shouldly;
using Xunit;

namespace MonixOne.Security.Authentication.Tests;

public sealed class OAuthAuthorizationPoliciesTests
{
    private const string RequiredScope = "resource.read";
    private const string OtherScope = "resource.write";
    private const string RequiredTenant = "lkb";
    private const string TenantPolicy = "tenant-access";
    private const string TenantScopePolicy = "tenant-scope-access";

    /// <summary>
    /// Проверяет разрешение доступа аутентифицированному principal с требуемым scope.
    /// </summary>
    [Fact]
    public async Task ScopePolicy_AuthenticatedPrincipalWithRequiredScope_Succeeds()
    {
        // Arrange
        await using var provider = CreateServiceProvider();
        var authorization = provider.GetRequiredService<IAuthorizationService>();
        var principal = CreatePrincipal(RequiredScope);

        // Act
        var result = await authorization.AuthorizeAsync(
            principal,
            resource: null,
            OAuthAuthorizationPolicies.ForScope(RequiredScope));

        // Assert
        result.Succeeded.ShouldBeTrue();
    }

    /// <summary>
    /// Проверяет запрет доступа, если token не содержит требуемый scope.
    /// </summary>
    [Fact]
    public async Task ScopePolicy_PrincipalWithoutRequiredScope_Fails()
    {
        // Arrange
        await using var provider = CreateServiceProvider();
        var authorization = provider.GetRequiredService<IAuthorizationService>();
        var principal = CreatePrincipal(OtherScope);

        // Act
        var result = await authorization.AuthorizeAsync(
            principal,
            resource: null,
            OAuthAuthorizationPolicies.ForScope(RequiredScope));

        // Assert
        result.Succeeded.ShouldBeFalse();
    }

    [Theory]
    [InlineData(true, "lkb", null, true)]
    [InlineData(false, "lkb", null, false)]
    [InlineData(true, "mbr", null, false)]
    [InlineData(true, "LKB", null, false)]
    [InlineData(true, "lkb-other", null, false)]
    [InlineData(true, null, null, false)]
    [InlineData(true, "", null, false)]
    [InlineData(true, " ", null, false)]
    [InlineData(true, "lkb", "lkb", false)]
    [InlineData(true, "lkb", "mbr", false)]
    [InlineData(true, "lkb", "", false)]
    public async Task TenantPolicy_RequiresSingleExactAuthenticatedTenant(
        bool isAuthenticated,
        string? tenantId,
        string? secondTenantId,
        bool expected)
    {
        await using var provider = CreateServiceProvider();
        var authorization = provider.GetRequiredService<IAuthorizationService>();
        var claims = new[] { tenantId, secondTenantId }
            .Where(value => value is not null)
            .Select(value => new Claim(OAuthTokenDefaults.TenantIdClaim, value!));
        var principal = new ClaimsPrincipal(new ClaimsIdentity(
            claims, authenticationType: isAuthenticated ? "Test" : null));

        var result = await authorization.AuthorizeAsync(principal, resource: null, TenantPolicy);

        result.Succeeded.ShouldBe(expected);
    }

    [Theory]
    [InlineData("resource.read", "lkb", true)]
    [InlineData("resource.read", "mbr", false)]
    [InlineData("resource.write", "lkb", false)]
    public async Task TenantScopePolicy_RequiresBothScopeAndTenant(string scope, string tenantId, bool expected)
    {
        await using var provider = CreateServiceProvider();
        var authorization = provider.GetRequiredService<IAuthorizationService>();
        var principal = new ClaimsPrincipal(new ClaimsIdentity(
        [
            new Claim(OAuthTokenDefaults.ScopeClaim, scope),
            new Claim(OAuthTokenDefaults.TenantIdClaim, tenantId)
        ], authenticationType: "Test"));

        var result = await authorization.AuthorizeAsync(principal, resource: null, TenantScopePolicy);

        result.Succeeded.ShouldBe(expected);
    }

    [Fact]
    public async Task TenantPolicy_IgnoresClaimsOfUnauthenticatedIdentity()
    {
        await using var provider = CreateServiceProvider();
        var authorization = provider.GetRequiredService<IAuthorizationService>();
        var principal = new ClaimsPrincipal(
        [
            new ClaimsIdentity(authenticationType: "Test"),
            new ClaimsIdentity([new Claim(OAuthTokenDefaults.TenantIdClaim, RequiredTenant)])
        ]);

        var result = await authorization.AuthorizeAsync(principal, resource: null, TenantPolicy);

        result.Succeeded.ShouldBeFalse();
    }

    [Theory]
    [InlineData("TENANT_ID")]
    [InlineData("Tenant_Id")]
    public async Task TenantPolicy_RequiresExactClaimType(string claimType)
    {
        await using var provider = CreateServiceProvider();
        var authorization = provider.GetRequiredService<IAuthorizationService>();
        var principal = new ClaimsPrincipal(new ClaimsIdentity(
            [new Claim(claimType, RequiredTenant)], authenticationType: "Test"));

        var result = await authorization.AuthorizeAsync(principal, resource: null, TenantPolicy);

        result.Succeeded.ShouldBeFalse();
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData(" ")]
    public void RequireTenant_RejectsMissingTenant(string? tenantId)
    {
        var policy = new AuthorizationPolicyBuilder();

        Should.Throw<ArgumentException>(() => policy.RequireTenant(tenantId!));
    }

    private static ServiceProvider CreateServiceProvider()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddAuthorization(options =>
        {
            options.AddScopePolicy(RequiredScope);
            options.AddPolicy(TenantPolicy, policy => policy.RequireTenant(RequiredTenant));
            options.AddPolicy(TenantScopePolicy, policy => policy
                .RequireScope(RequiredScope)
                .RequireTenant(RequiredTenant));
        });
        return services.BuildServiceProvider();
    }

    private static ClaimsPrincipal CreatePrincipal(string scope) =>
        new(new ClaimsIdentity(
        [
            new Claim(OAuthTokenDefaults.ScopeClaim, scope)
        ], authenticationType: "Test"));
}
