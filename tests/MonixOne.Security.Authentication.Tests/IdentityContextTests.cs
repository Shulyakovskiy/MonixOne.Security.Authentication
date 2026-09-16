using System.Security.Claims;
using Microsoft.AspNetCore.Http;
using Shouldly;
using Xunit;

namespace MonixOne.Security.Authentication.Tests;

public sealed class IdentityContextTests
{
    [Fact]
    public void AuthenticatedUser_ReturnsSubjectRolesAndScopesFromTokenClaims()
    {
        var request = CreateRequest(
            isAuthenticated: true,
            new Claim(OAuthTokenDefaults.SubjectClaim, "01a0a3b9-952e-79eb-8e98-02699a0566e9"),
            new Claim(OAuthTokenDefaults.RoleClaim, "Admin"),
            new Claim(OAuthTokenDefaults.RoleClaim, "Manager"),
            new Claim(OAuthTokenDefaults.RoleClaim, "Admin"),
            new Claim(OAuthTokenDefaults.ScopeClaim, "openid offline_access location-service.full_access"),
            new Claim(OAuthTokenDefaults.ScopeClaim, "mobile-app.full_access openid"));

        request.UserId.ShouldBe("01a0a3b9-952e-79eb-8e98-02699a0566e9");
        request.Roles.ShouldBe(["Admin", "Manager"]);
        request.Scopes.ShouldBe(
        [
            "openid",
            "offline_access",
            "location-service.full_access",
            "mobile-app.full_access"
        ]);
    }

    [Fact]
    public void NoHttpContext_ReturnsEmptyValues()
    {
        var request = new IdentityContext(new HttpContextAccessor());

        request.UserId.ShouldBeNull();
        request.Roles.ShouldBeEmpty();
        request.Scopes.ShouldBeEmpty();
    }

    [Fact]
    public void UnauthenticatedUserWithClaims_ReturnsEmptyValues()
    {
        var request = CreateRequest(
            isAuthenticated: false,
            new Claim(OAuthTokenDefaults.SubjectClaim, "01a0a3b9-952e-79eb-8e98-02699a0566e9"),
            new Claim(OAuthTokenDefaults.RoleClaim, "Admin"),
            new Claim(OAuthTokenDefaults.ScopeClaim, "location-service.full_access"));

        request.UserId.ShouldBeNull();
        request.Roles.ShouldBeEmpty();
        request.Scopes.ShouldBeEmpty();
    }

    private static IdentityContext CreateRequest(bool isAuthenticated, params Claim[] claims)
    {
        var identity = new ClaimsIdentity(
            claims,
            authenticationType: isAuthenticated ? "Test" : null);
        var context = new DefaultHttpContext
        {
            User = new ClaimsPrincipal(identity)
        };

        return new IdentityContext(new HttpContextAccessor { HttpContext = context });
    }
}
