using Duende.AccessTokenManagement;
using Duende.IdentityModel.Client;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Http.Resilience;
using Refit;

namespace MonixOne.Security.Authentication;

/// <summary>
/// Регистрация исходящих HTTP-клиентов с client credentials authentication.
/// </summary>
public static class ServiceClientServiceCollectionExtensions
{
    /// <summary>
    /// Регистрирует настроенные контракты исходящих сервисов.
    /// </summary>
    /// <remarks>
    /// Если секция <c>ServiceClients</c> отсутствует или <c>Services</c> пуста,
    /// метод не меняет контейнер и не читает client credentials.
    /// </remarks>
    public static IServiceCollection AddServiceClients(
        this IServiceCollection services,
        IConfiguration configuration,
        IConfiguration identityConfiguration,
        Action<ServiceClientRegistrar> registerContracts)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configuration);
        ArgumentNullException.ThrowIfNull(identityConfiguration);
        ArgumentNullException.ThrowIfNull(registerContracts);

        var section = configuration.GetSection(ServiceClientsOptions.SectionName);
        if (!section.Exists())
            return services;

        var options = section.Get<ServiceClientsOptions>();
        if (options is null || !options.HasServices)
            return services;

        options.Validate();
        services.AddSingleton(options);

        var registrar = new ServiceClientRegistrar(
            services,
            options,
            section.GetSection(ServiceClientsOptions.ResilienceSectionName),
            services.AddClientCredentialsTokenManagement,
            () => CreateClientCredentialsOptions(identityConfiguration));

        registerContracts(registrar);
        return services;
    }

    private static ClientCredentialsClient CreateClientCredentialsOptions(
        IConfiguration identityConfiguration)
    {
        var authority = identityConfiguration["Authority"];
        if (!Uri.TryCreate(authority, UriKind.Absolute, out var authorityUri)
            || (authorityUri.Scheme != Uri.UriSchemeHttp
                && authorityUri.Scheme != Uri.UriSchemeHttps)
            || string.IsNullOrWhiteSpace(authorityUri.Host)
            || !string.IsNullOrEmpty(authorityUri.UserInfo)
            || !string.IsNullOrEmpty(authorityUri.Query)
            || !string.IsNullOrEmpty(authorityUri.Fragment))
        {
            throw new InvalidOperationException(
                "Identity:Authority должен быть абсолютным HTTP(S) URI без user info, query-параметров и fragment.");
        }

        var clientId = identityConfiguration["ClientId"];
        if (string.IsNullOrWhiteSpace(clientId))
            throw new InvalidOperationException("Identity:ClientId должен быть настроен.");

        var clientSecret = identityConfiguration["ClientSecret"];
        if (string.IsNullOrWhiteSpace(clientSecret))
            throw new InvalidOperationException("Identity:ClientSecret должен быть настроен.");

        return new ClientCredentialsClient
        {
            TokenEndpoint = new Uri($"{authorityUri.AbsoluteUri.TrimEnd('/')}/connect/token", UriKind.Absolute),
            ClientId = ClientId.Parse(clientId),
            ClientSecret = ClientSecret.Parse(clientSecret),
            ClientCredentialStyle = ClientCredentialStyle.PostBody
        };
    }
}

/// <summary>
/// Регистрирует Refit-контракты для настроенных групп сервисов.
/// </summary>
public sealed class ServiceClientRegistrar
{
    private readonly IServiceCollection _services;
    private readonly ServiceClientsOptions _serviceClients;
    private readonly IConfigurationSection _resilienceSection;
    private readonly Func<ClientCredentialsTokenManagementBuilder> _createTokenManagement;
    private readonly Func<ClientCredentialsClient> _createClientCredentials;
    private readonly HashSet<string> _registeredGroups = new(StringComparer.OrdinalIgnoreCase);
    private ClientCredentialsTokenManagementBuilder? _tokenManagement;
    private ClientCredentialsClient? _clientCredentials;

    internal ServiceClientRegistrar(
        IServiceCollection services,
        ServiceClientsOptions serviceClients,
        IConfigurationSection resilienceSection,
        Func<ClientCredentialsTokenManagementBuilder> createTokenManagement,
        Func<ClientCredentialsClient> createClientCredentials)
    {
        _services = services;
        _serviceClients = serviceClients;
        _resilienceSection = resilienceSection;
        _createTokenManagement = createTokenManagement;
        _createClientCredentials = createClientCredentials;
    }

    /// <summary>
    /// Регистрирует контракт, если его группа задана в <c>ServiceClients:Services</c>.
    /// </summary>
    public void Add<TClient>(string group)
        where TClient : class
    {
        if (!_serviceClients.TryGetService(group, out var service))
            return;

        var tokenClientName = ClientCredentialsClientName.Parse(service.Group);
        if (_registeredGroups.Add(service.Group))
        {
            var credentials = _clientCredentials ??= _createClientCredentials();
            (_tokenManagement ??= _createTokenManagement()).AddClient(tokenClientName, client =>
            {
                client.TokenEndpoint = credentials.TokenEndpoint;
                client.ClientId = credentials.ClientId;
                client.ClientSecret = credentials.ClientSecret;
                client.ClientCredentialStyle = credentials.ClientCredentialStyle;
                client.Scope = Scope.Parse(string.Join(' ', service.Scopes));
            });
        }

        var clientBuilder = _services
            .AddRefitGeneratedClient<TClient>(new RefitSettings(), service.Group)
            .ConfigureHttpClient(client => client.BaseAddress = service.BaseAddress)
            .AddClientCredentialsTokenHandler(tokenClientName);

        var resilienceBuilder = _resilienceSection.Exists()
            ? clientBuilder.AddStandardResilienceHandler(_resilienceSection)
            : clientBuilder.AddStandardResilienceHandler();
        resilienceBuilder.Configure(options => options.Retry.DisableForUnsafeHttpMethods());
    }
}
