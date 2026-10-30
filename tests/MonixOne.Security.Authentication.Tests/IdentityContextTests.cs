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
            new Claim(
                OAuthTokenDefaults.SubjectExternalClaim,
                "01a0a3b9-952e-79eb-8e98-02699a0566e9"
            ),
            new Claim(OAuthTokenDefaults.TenantIdClaim, "lkb"),
            new Claim(OAuthTokenDefaults.RoleClaim, "Admin"),
            new Claim(OAuthTokenDefaults.RoleClaim, "Manager"),
            new Claim(OAuthTokenDefaults.RoleClaim, "Admin"),
            new Claim(
                OAuthTokenDefaults.ScopeClaim,
                "openid offline_access location-service.full_access"
            ),
            new Claim(OAuthTokenDefaults.ScopeClaim, "mobile-app.full_access openid")
        );

        request.IsAuthenticated.ShouldBeTrue();
        request.UserId.ShouldBe("01a0a3b9-952e-79eb-8e98-02699a0566e9");
        request.ExternalUserId.ShouldBe("01a0a3b9-952e-79eb-8e98-02699a0566e9");
        request.TenantId.ShouldBe("lkb");
        request.GetRoles().ShouldBe(["Admin", "Manager"]);
        request
            .GetScopes()
            .ShouldBe([
                "openid",
                "offline_access",
                "location-service.full_access",
                "mobile-app.full_access",
            ]);
    }

    [Fact]
    public void AuthenticatedUserWithoutClaims_IsAuthenticatedWithEmptyValues()
    {
        var request = CreateRequest(isAuthenticated: true);

        request.IsAuthenticated.ShouldBeTrue();
        request.UserId.ShouldBeNull();
        request.ExternalUserId.ShouldBeNull();
        request.TenantId.ShouldBeNull();
        request.GetRoles().ShouldBeEmpty();
        request.GetScopes().ShouldBeEmpty();
    }

    [Fact]
    public void NoHttpContext_ReturnsEmptyValues()
    {
        var request = new IdentityContext(new HttpContextAccessor());

        request.IsAuthenticated.ShouldBeFalse();
        request.UserId.ShouldBeNull();
        request.ExternalUserId.ShouldBeNull();
        request.TenantId.ShouldBeNull();
        request.GetRoles().ShouldBeEmpty();
        request.GetScopes().ShouldBeEmpty();
    }

    [Fact]
    public void UnauthenticatedUserWithClaims_ReturnsEmptyValues()
    {
        var request = CreateRequest(
            isAuthenticated: false,
            new Claim(OAuthTokenDefaults.SubjectClaim, "01a0a3b9-952e-79eb-8e98-02699a0566e9"),
            new Claim(OAuthTokenDefaults.TenantIdClaim, "lkb"),
            new Claim(OAuthTokenDefaults.RoleClaim, "Admin"),
            new Claim(OAuthTokenDefaults.ScopeClaim, "location-service.full_access")
        );

        request.IsAuthenticated.ShouldBeFalse();
        request.UserId.ShouldBeNull();
        request.ExternalUserId.ShouldBeNull();
        request.TenantId.ShouldBeNull();
        request.GetRoles().ShouldBeEmpty();
        request.GetScopes().ShouldBeEmpty();
    }

    [Theory]
    [InlineData("mbr", null, "mbr")]
    [InlineData("lkb", null, "lkb")]
    [InlineData("Customer-A", null, "Customer-A")]
    [InlineData(null, null, null)]
    [InlineData("", null, null)]
    [InlineData(" ", null, null)]
    [InlineData("lkb", "lkb", null)]
    [InlineData("lkb", "mbr", null)]
    [InlineData("lkb", "", null)]
    public void TenantId_ReturnsOnlySingleNonEmptyClaim(
        string? tenantId,
        string? secondTenantId,
        string? expected
    )
    {
        var claims = new[] { tenantId, secondTenantId }
            .Where(value => value is not null)
            .Select(value => new Claim(OAuthTokenDefaults.TenantIdClaim, value!))
            .ToArray();
        var request = CreateRequest(isAuthenticated: true, claims);

        request.TenantId.ShouldBe(expected);
    }

    private static IIdentityContext CreateRequest(bool isAuthenticated, params Claim[] claims)
    {
        var identity = new ClaimsIdentity(
            claims,
            authenticationType: isAuthenticated ? "Test" : null
        );
        var context = new DefaultHttpContext { User = new ClaimsPrincipal(identity) };

        return new IdentityContext(new HttpContextAccessor { HttpContext = context });
    }
}
