using System.Collections.Concurrent;
using System.Net;
using System.Text;
using Duende.AccessTokenManagement;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Refit;
using Shouldly;
using Xunit;

namespace MonixOne.Security.Authentication.Tests;

public sealed class ServiceClientServiceCollectionExtensionsTests
{
    [Fact]
    public void AddServiceClients_when_section_is_missing_does_not_require_identity_configuration()
    {
        var services = new ServiceCollection();
        var configuration = new ConfigurationBuilder().Build();

        services.AddServiceClients(
            configuration.GetSection("Infrastructure"),
            configuration.GetSection("Identity"),
            RegisterProfileContract
        );

        using var provider = services.BuildServiceProvider();
        provider.GetService<IProfileService>().ShouldBeNull();
    }

    [Fact]
    public void AddServiceClients_when_services_are_empty_does_not_register_contract()
    {
        var services = new ServiceCollection();
        var configuration = CreateConfiguration(
            new Dictionary<string, string?> { ["Infrastructure:ServiceClients"] = string.Empty }
        );

        services.AddServiceClients(
            configuration.GetRequiredSection("Infrastructure"),
            configuration.GetSection("Identity"),
            RegisterProfileContract
        );

        using var provider = services.BuildServiceProvider();
        provider.GetService<IProfileService>().ShouldBeNull();
    }

    [Fact]
    public void AddServiceClients_when_group_is_configured_registers_contract()
    {
        var services = new ServiceCollection();
        var configuration = CreateConfiguredProfileClient();

        services.AddServiceClients(
            configuration.GetRequiredSection("Infrastructure"),
            configuration.GetRequiredSection("Identity"),
            RegisterProfileContract
        );

        using var provider = services.BuildServiceProvider();
        var httpClient = provider
            .GetRequiredService<IHttpClientFactory>()
            .CreateClient(ProfileServiceGroup.Name);

        httpClient.BaseAddress.ShouldBe(new Uri("http://profile.test:8000"));
        provider.GetRequiredService<IProfileService>().ShouldNotBeNull();
    }

    [Theory]
    [InlineData(null)]
    [InlineData("ClientCredentials")]
    public async Task AddServiceClients_uses_client_credentials_and_caches_access_token(
        string? authentication
    )
    {
        var identityHandler = new RecordingHandler(
            """
            {"access_token":"service-access-token","expires_in":3600}
            """
        );
        var profileHandler = new RecordingHandler("""{"id":"profile-1"}""");
        var services = new ServiceCollection();
        var configuration = CreateConfiguredProfileClient();
        if (authentication is not null)
            configuration["Infrastructure:ServiceClients:Services:0:Authentication"] =
                authentication;

        services.AddServiceClients(
            configuration.GetRequiredSection("Infrastructure"),
            configuration.GetRequiredSection("Identity"),
            RegisterProfileContract
        );
        services
            .AddHttpClient(ClientCredentialsTokenManagementDefaults.BackChannelHttpClientName)
            .ConfigurePrimaryHttpMessageHandler(() => identityHandler);
        services
            .AddHttpClient(ProfileServiceGroup.Name)
            .ConfigurePrimaryHttpMessageHandler(() => profileHandler);

        using var provider = services.BuildServiceProvider();
        var profileClient = provider.GetRequiredService<IProfileService>();

        var first = await profileClient.GetCurrent(TestContext.Current.CancellationToken);
        var second = await profileClient.GetCurrent(TestContext.Current.CancellationToken);

        first.Id.ShouldBe("profile-1");
        second.Id.ShouldBe("profile-1");

        identityHandler.CallCount.ShouldBe(1);
        identityHandler.Requests.Single().Method.ShouldBe(HttpMethod.Post);
        identityHandler
            .Requests.Single()
            .Uri.ShouldBe(new Uri("http://identity.test:8000/identity/connect/token"));
        identityHandler.Requests.Single().Body.ShouldContain("grant_type=client_credentials");
        identityHandler.Requests.Single().Body.ShouldContain("client_id=location-service");
        identityHandler.Requests.Single().Body.ShouldContain("client_secret=test-client-secret");
        identityHandler.Requests.Single().Body.ShouldContain("scope=profile-service.intra_read");

        profileHandler.CallCount.ShouldBe(2);
        foreach (var request in profileHandler.Requests)
            request.Authorization.ShouldBe("Bearer service-access-token");
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task AddServiceClients_with_none_calls_postgrest_without_identity_scopes_or_authorization(
        bool passNullIdentity
    )
    {
        var identityHandler = new RecordingHandler(
            """{"access_token":"unexpected-token","expires_in":3600}"""
        );
        var postgrestHandler = new RecordingHandler("""[{"id":1,"name":"Moscow"}]""");
        var services = new ServiceCollection();
        var configuration = CreateConfiguration(
            new Dictionary<string, string?>
            {
                ["Infrastructure:ServiceClients:Services:0:Group"] = "postgrest",
                ["Infrastructure:ServiceClients:Services:0:BaseAddress"] =
                    "http://postgrest.test:3000",
                ["Infrastructure:ServiceClients:Services:0:Authentication"] = "None",
            }
        );

        services.AddServiceClients(
            configuration.GetRequiredSection("Infrastructure"),
            passNullIdentity ? null : configuration.GetSection("Identity"),
            registrar => registrar.Add<IPostgRestService>("postgrest")
        );
        services
            .AddHttpClient(ClientCredentialsTokenManagementDefaults.BackChannelHttpClientName)
            .ConfigurePrimaryHttpMessageHandler(() => identityHandler);
        services
            .AddHttpClient("postgrest")
            .ConfigurePrimaryHttpMessageHandler(() => postgrestHandler);

        using var provider = services.BuildServiceProvider();
        provider.GetService<IClientCredentialsTokenManager>().ShouldBeNull();
        var client = provider.GetRequiredService<IPostgRestService>();

        var locations = await client.GetLocations("id,name", TestContext.Current.CancellationToken);

        locations.Single().ShouldBe(new LocationResponse(1, "Moscow"));
        identityHandler.CallCount.ShouldBe(0);
        var request = postgrestHandler.Requests.Single();
        request.Method.ShouldBe(HttpMethod.Get);
        request.Uri!.GetLeftPart(UriPartial.Path).ShouldBe("http://postgrest.test:3000/locations");
        request.Authorization.ShouldBeNull();
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task AddServiceClients_with_mixed_groups_only_authenticates_client_credentials_group(
        bool anonymousFirst
    )
    {
        var identityHandler = new RecordingHandler(
            """{"access_token":"service-access-token","expires_in":3600}"""
        );
        var profileHandler = new RecordingHandler("""{"id":"profile-1"}""");
        var postgrestHandler = new RecordingHandler("""[{"id":1,"name":"Moscow"}]""");
        var services = new ServiceCollection();
        var configuration = CreateConfiguredProfileClient();
        configuration["Infrastructure:ServiceClients:Services:1:Group"] = "postgrest";
        configuration["Infrastructure:ServiceClients:Services:1:BaseAddress"] =
            "http://postgrest.test:3000";
        configuration["Infrastructure:ServiceClients:Services:1:Authentication"] = "None";

        services.AddServiceClients(
            configuration.GetRequiredSection("Infrastructure"),
            configuration.GetRequiredSection("Identity"),
            registrar =>
            {
                if (anonymousFirst)
                    registrar.Add<IPostgRestService>("postgrest");

                RegisterProfileContract(registrar);

                if (!anonymousFirst)
                    registrar.Add<IPostgRestService>("postgrest");
            }
        );
        services
            .AddHttpClient(ClientCredentialsTokenManagementDefaults.BackChannelHttpClientName)
            .ConfigurePrimaryHttpMessageHandler(() => identityHandler);
        services
            .AddHttpClient(ProfileServiceGroup.Name)
            .ConfigurePrimaryHttpMessageHandler(() => profileHandler);
        services
            .AddHttpClient("postgrest")
            .ConfigurePrimaryHttpMessageHandler(() => postgrestHandler);

        using var provider = services.BuildServiceProvider();
        var profileClient = provider.GetRequiredService<IProfileService>();
        var postgrestClient = provider.GetRequiredService<IPostgRestService>();

        await postgrestClient.GetLocations("id,name", TestContext.Current.CancellationToken);
        identityHandler.CallCount.ShouldBe(0);

        await profileClient.GetCurrent(TestContext.Current.CancellationToken);
        await postgrestClient.GetLocations("id,name", TestContext.Current.CancellationToken);

        identityHandler.CallCount.ShouldBe(1);
        profileHandler.Requests.Single().Authorization.ShouldBe("Bearer service-access-token");
        postgrestHandler.CallCount.ShouldBe(2);
        foreach (var request in postgrestHandler.Requests)
            request.Authorization.ShouldBeNull();
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData(" ")]
    public void AddServiceClients_with_client_credentials_rejects_missing_or_blank_scopes(
        string? scope
    )
    {
        var services = new ServiceCollection();
        var configuration = CreateConfiguredProfileClient();
        configuration["Infrastructure:ServiceClients:Services:0:Scopes:0"] = scope;

        var exception = Should.Throw<InvalidOperationException>(() =>
            services.AddServiceClients(
                configuration.GetRequiredSection("Infrastructure"),
                configuration.GetRequiredSection("Identity"),
                RegisterProfileContract
            )
        );

        exception.Message.ShouldContain("Scopes");
        exception.Message.ShouldContain(ProfileServiceGroup.Name);
    }

    [Theory]
    [InlineData("Authority")]
    [InlineData("ClientId")]
    [InlineData("ClientSecret")]
    public void AddServiceClients_with_client_credentials_rejects_missing_identity_settings(
        string setting
    )
    {
        var services = new ServiceCollection();
        var configuration = CreateConfiguredProfileClient();
        configuration[$"Identity:{setting}"] = null;

        var exception = Should.Throw<InvalidOperationException>(() =>
            services.AddServiceClients(
                configuration.GetRequiredSection("Infrastructure"),
                configuration.GetSection("Identity"),
                RegisterProfileContract
            )
        );

        exception.Message.ShouldContain($"Identity:{setting}");
    }

    [Fact]
    public void AddServiceClients_with_client_credentials_rejects_null_identity_configuration()
    {
        var services = new ServiceCollection();
        var configuration = CreateConfiguredProfileClient();

        var exception = Should.Throw<ArgumentNullException>(() =>
            services.AddServiceClients(
                configuration.GetRequiredSection("Infrastructure"),
                null,
                RegisterProfileContract
            )
        );

        exception.ParamName.ShouldBe("identityConfiguration");
    }

    [Theory]
    [InlineData("Unknown")]
    [InlineData("42")]
    public void AddServiceClients_rejects_unknown_authentication(string authentication)
    {
        var services = new ServiceCollection();
        var configuration = CreateConfiguredProfileClient();
        configuration["Infrastructure:ServiceClients:Services:0:Authentication"] = authentication;

        var exception = Should.Throw<InvalidOperationException>(() =>
            services.AddServiceClients(
                configuration.GetRequiredSection("Infrastructure"),
                configuration.GetRequiredSection("Identity"),
                RegisterProfileContract
            )
        );

        exception.Message.ShouldContain("Authentication");
    }

    private static void RegisterProfileContract(ServiceClientRegistrar registrar)
    {
        // Регистрация контракта
        registrar.Add<IProfileService>(ProfileServiceGroup.Name);
    }

    private static IConfiguration CreateConfiguredProfileClient()
    {
        return CreateConfiguration(
            new Dictionary<string, string?>
            {
                ["Identity:Authority"] = "http://identity.test:8000/identity",
                ["Identity:ClientId"] = "location-service",
                ["Identity:ClientSecret"] = "test-client-secret",
                ["Infrastructure:ServiceClients:Services:0:Group"] = ProfileServiceGroup.Name,
                ["Infrastructure:ServiceClients:Services:0:BaseAddress"] =
                    "http://profile.test:8000",
                ["Infrastructure:ServiceClients:Services:0:Scopes:0"] =
                    "profile-service.intra_read",
            }
        );
    }

    private static IConfiguration CreateConfiguration(IReadOnlyDictionary<string, string?> values)
    {
        return new ConfigurationBuilder().AddInMemoryCollection(values).Build();
    }

    public interface IProfileService
    {
        [Get("/api/v1/profiles/current")]
        Task<ProfileResponse> GetCurrent(CancellationToken ct);
    }

    public interface IPostgRestService
    {
        [Get("/locations")]
        Task<LocationResponse[]> GetLocations(
            [AliasAs("select")] string select,
            CancellationToken ct
        );
    }

    private static class ProfileServiceGroup
    {
        public const string Name = "profile";
    }

    public sealed record ProfileResponse(string Id);

    public sealed record LocationResponse(int Id, string Name);

    private sealed class RecordingHandler(string responseBody) : HttpMessageHandler
    {
        private readonly ConcurrentQueue<RecordedRequest> _requests = [];

        public int CallCount => _requests.Count;
        public IReadOnlyCollection<RecordedRequest> Requests => _requests.ToArray();

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken ct
        )
        {
            var body = request.Content is null
                ? string.Empty
                : await request.Content.ReadAsStringAsync(ct);
            _requests.Enqueue(
                new RecordedRequest(
                    request.Method,
                    request.RequestUri,
                    request.Headers.Authorization?.ToString(),
                    body
                )
            );

            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(responseBody, Encoding.UTF8, "application/json"),
            };
        }
    }

    private sealed record RecordedRequest(
        HttpMethod Method,
        Uri? Uri,
        string? Authorization,
        string Body
    );
}
