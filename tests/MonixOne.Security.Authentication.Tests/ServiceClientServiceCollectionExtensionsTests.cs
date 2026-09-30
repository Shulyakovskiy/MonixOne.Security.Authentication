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
            RegisterProfileContract);

        using var provider = services.BuildServiceProvider();
        provider.GetService<IProfileService>().ShouldBeNull();
    }

    [Fact]
    public void AddServiceClients_when_services_are_empty_does_not_register_contract()
    {
        var services = new ServiceCollection();
        var configuration = CreateConfiguration(new Dictionary<string, string?>
        {
            ["Infrastructure:ServiceClients"] = string.Empty
        });

        services.AddServiceClients(
            configuration.GetRequiredSection("Infrastructure"),
            configuration.GetSection("Identity"),
            RegisterProfileContract);

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
            RegisterProfileContract);

        using var provider = services.BuildServiceProvider();
        var httpClient = provider.GetRequiredService<IHttpClientFactory>().CreateClient(ProfileServiceGroup.Name);

        httpClient.BaseAddress.ShouldBe(new Uri("http://profile.test:8000"));
        provider.GetRequiredService<IProfileService>().ShouldNotBeNull();
    }

    [Fact]
    public async Task AddServiceClients_uses_client_credentials_and_caches_access_token()
    {
        var identityHandler = new RecordingHandler(
            """
            {"access_token":"service-access-token","expires_in":3600}
            """);
        var profileHandler = new RecordingHandler("""{"id":"profile-1"}""");
        var services = new ServiceCollection();
        var configuration = CreateConfiguredProfileClient();

        services.AddServiceClients(
            configuration.GetRequiredSection("Infrastructure"),
            configuration.GetRequiredSection("Identity"),
            RegisterProfileContract);
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
        identityHandler.Requests.Single().Uri.ShouldBe(new Uri("http://identity.test:8000/identity/connect/token"));
        identityHandler.Requests.Single().Body.ShouldContain("grant_type=client_credentials");
        identityHandler.Requests.Single().Body.ShouldContain("client_id=location-service");
        identityHandler.Requests.Single().Body.ShouldContain("client_secret=test-client-secret");
        identityHandler.Requests.Single().Body.ShouldContain("scope=profile-service.intra_read");

        profileHandler.CallCount.ShouldBe(2);
        foreach (var request in profileHandler.Requests)
            request.Authorization.ShouldBe("Bearer service-access-token");
    }

    private static void RegisterProfileContract(ServiceClientRegistrar registrar)
    {
        // Регистрация контракта
        registrar.Add<IProfileService>(ProfileServiceGroup.Name);
    }

    private static IConfiguration CreateConfiguredProfileClient()
    {
        return CreateConfiguration(new Dictionary<string, string?>
        {
            ["Identity:Authority"] = "http://identity.test:8000/identity",
            ["Identity:ClientId"] = "location-service",
            ["Identity:ClientSecret"] = "test-client-secret",
            ["Infrastructure:ServiceClients:Services:0:Group"] = ProfileServiceGroup.Name,
            ["Infrastructure:ServiceClients:Services:0:BaseAddress"] = "http://profile.test:8000",
            ["Infrastructure:ServiceClients:Services:0:Scopes:0"] = "profile-service.intra_read"
        });
    }

    private static IConfiguration CreateConfiguration(IReadOnlyDictionary<string, string?> values)
    {
        return new ConfigurationBuilder()
            .AddInMemoryCollection(values)
            .Build();
    }

    public interface IProfileService
    {
        [Get("/api/v1/profiles/current")]
        Task<ProfileResponse> GetCurrent(CancellationToken ct);
    }

    private static class ProfileServiceGroup
    {
        public const string Name = "profile";
    }

    public sealed record ProfileResponse(string Id);

    private sealed class RecordingHandler(string responseBody) : HttpMessageHandler
    {
        private readonly ConcurrentQueue<RecordedRequest> _requests = [];

        public int CallCount => _requests.Count;
        public IReadOnlyCollection<RecordedRequest> Requests => _requests.ToArray();

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken ct)
        {
            var body = request.Content is null
                ? string.Empty
                : await request.Content.ReadAsStringAsync(ct);
            _requests.Enqueue(new RecordedRequest(
                request.Method,
                request.RequestUri,
                request.Headers.Authorization?.ToString(),
                body));

            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(responseBody, Encoding.UTF8, "application/json")
            };
        }
    }

    private sealed record RecordedRequest(
        HttpMethod Method,
        Uri? Uri,
        string? Authorization,
        string Body);
}
