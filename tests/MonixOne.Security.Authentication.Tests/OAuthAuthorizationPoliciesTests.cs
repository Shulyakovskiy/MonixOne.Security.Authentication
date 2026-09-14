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

    private static ServiceProvider CreateServiceProvider()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddAuthorization(options => options.AddScopePolicy(RequiredScope));
        return services.BuildServiceProvider();
    }

    private static ClaimsPrincipal CreatePrincipal(string scope) =>
        new(new ClaimsIdentity(
        [
            new Claim(OAuthTokenDefaults.ScopeClaim, scope)
        ], authenticationType: "Test"));
}
