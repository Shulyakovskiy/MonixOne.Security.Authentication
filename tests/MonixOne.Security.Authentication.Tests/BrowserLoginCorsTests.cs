using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Cors.Infrastructure;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Shouldly;
using Xunit;

namespace MonixOne.Security.Authentication.Tests;

public sealed class BrowserLoginCorsTests
{
    [Theory]
    [InlineData("https://admin.example.test", true)]
    [InlineData("https://outside.example.test", false)]
    [InlineData("https://admin.example.test:8443", false)]
    [InlineData("https://admin.example.test.outside.test", false)]
    public async Task Preflight_AllowsCredentialsOnlyForExactConfiguredOrigin(
        string origin,
        bool allowed
    )
    {
        // Arrange
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(
                new Dictionary<string, string?>
                {
                    ["Cors:Origins:0"] = "https://admin.example.test",
                }
            )
            .Build();
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddBrowserLoginCors(configuration);
        await using var provider = services.BuildServiceProvider();
        var app = new ApplicationBuilder(provider);
        app.UseBrowserLoginCors();
        var reachedEndpoint = false;
        app.Run(_ =>
        {
            reachedEndpoint = true;
            return Task.CompletedTask;
        });
        var context = Preflight(provider, origin);

        // Act
        await app.Build()(context);

        // Assert
        context.Response.StatusCode.ShouldBe(StatusCodes.Status204NoContent);
        reachedEndpoint.ShouldBeFalse();
        if (allowed)
        {
            context.Response.Headers["Access-Control-Allow-Origin"].ToString().ShouldBe(origin);
            context
                .Response.Headers["Access-Control-Allow-Credentials"]
                .ToString()
                .ShouldBe("true");
            context.Response.Headers["Access-Control-Allow-Methods"].ToString().ShouldBe("POST");
            context
                .Response.Headers["Access-Control-Allow-Headers"]
                .ToString()
                .ShouldBe("Content-Type");
        }
        else
            context.Response.Headers.ContainsKey("Access-Control-Allow-Origin").ShouldBeFalse();
    }

    [Fact]
    public async Task WithoutOrigins_DoesNotAllowCrossOriginAccess()
    {
        // Arrange
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddBrowserLoginCors(new ConfigurationBuilder().Build());
        await using var provider = services.BuildServiceProvider();
        var app = new ApplicationBuilder(provider);
        app.UseBrowserLoginCors();
        var context = Preflight(provider, "https://admin.example.test");

        // Act
        await app.Build()(context);

        // Assert
        context.Response.Headers.ContainsKey("Access-Control-Allow-Origin").ShouldBeFalse();
        context.Response.Headers.ContainsKey("Access-Control-Allow-Credentials").ShouldBeFalse();
    }

    [Fact]
    public void WildcardOriginWithCredentials_IsRejectedByFramework()
    {
        // Arrange
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?> { ["Cors:Origins:0"] = "*" })
            .Build();
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddBrowserLoginCors(configuration);
        using var provider = services.BuildServiceProvider();

        // Act / Assert
        Should.Throw<InvalidOperationException>(() =>
            provider.GetRequiredService<IOptions<CorsOptions>>().Value
        );
    }

    private static DefaultHttpContext Preflight(IServiceProvider provider, string origin)
    {
        var context = new DefaultHttpContext { RequestServices = provider };
        context.Request.Method = HttpMethods.Options;
        context.Request.Headers.Origin = origin;
        context.Request.Headers["Access-Control-Request-Method"] = "POST";
        context.Request.Headers["Access-Control-Request-Headers"] = "content-type";
        return context;
    }
}
