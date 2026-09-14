using System.Security.Claims;
using Shouldly;
using Xunit;

namespace MonixOne.Security.Authentication.Tests;

public sealed class ClaimsPrincipalExtensionsTests
{
    private const string ReadScope = "resource.read";
    private const string WriteScope = "resource.write";

    /// <summary>
    /// Проверяет поиск scope в claim, содержащем несколько значений через пробел.
    /// </summary>
    [Fact]
    public void HasScope_SpaceSeparatedClaim_FindsExactScope()
    {
        // Arrange
        var principal = CreatePrincipal($"{ReadScope} {WriteScope}");

        // Act
        var hasScope = principal.HasScope(WriteScope);

        // Assert
        hasScope.ShouldBeTrue();
    }

    /// <summary>
    /// Проверяет поиск scope среди нескольких одноимённых claims.
    /// </summary>
    [Fact]
    public void HasScope_RepeatedClaims_FindsExactScope()
    {
        // Arrange
        var principal = CreatePrincipal(ReadScope, WriteScope);

        // Act
        var hasScope = principal.HasScope(WriteScope);

        // Assert
        hasScope.ShouldBeTrue();
    }

    /// <summary>
    /// Проверяет отсутствие частичного совпадения имени scope.
    /// </summary>
    [Fact]
    public void HasScope_PartialScopeName_ReturnsFalse()
    {
        // Arrange
        var principal = CreatePrincipal(WriteScope);

        // Act
        var hasScope = principal.HasScope("resource");

        // Assert
        hasScope.ShouldBeFalse();
    }

    private static ClaimsPrincipal CreatePrincipal(params string[] scopes) =>
        new(new ClaimsIdentity(
            scopes.Select(scope => new Claim(OAuthTokenDefaults.ScopeClaim, scope)),
            authenticationType: "Test"));
}
