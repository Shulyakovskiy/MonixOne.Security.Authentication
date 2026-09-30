using System.Diagnostics.CodeAnalysis;

namespace MonixOne.Security.Authentication;

/// <summary>
/// Настройки исходящих HTTP-клиентов, использующих client credentials.
/// </summary>
public sealed class ServiceClientsOptions
{
    /// <summary>
    /// Имя секции с настройками клиентов.
    /// </summary>
    public const string SectionName = "ServiceClients";

    /// <summary>
    /// Имя вложенной секции с настройками resilience pipeline.
    /// </summary>
    public const string ResilienceSectionName = "Resilience";

    /// <summary>
    /// Список внешних сервисов, доступных приложению.
    /// </summary>
    public ServiceClientOptions[] Services { get; init; } = [];

    /// <summary>
    /// Признак наличия хотя бы одного настроенного клиента.
    /// </summary>
    public bool HasServices => Services.Length > 0;

    /// <summary>
    /// Ищет настройки сервиса по группе.
    /// </summary>
    public bool TryGetService(
        string group,
        [NotNullWhen(true)] out ServiceClientOptions? service)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(group);

        service = Services.FirstOrDefault(candidate =>
            string.Equals(candidate.Group, group, StringComparison.OrdinalIgnoreCase));
        return service is not null;
    }

    internal void Validate()
    {
        var groups = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var service in Services)
        {
            if (string.IsNullOrWhiteSpace(service.Group))
                throw new InvalidOperationException("ServiceClients:Services:Group не должен быть пустым.");

            if (!groups.Add(service.Group))
            {
                throw new InvalidOperationException(
                    $"ServiceClients содержит повторяющуюся группу '{service.Group}'.");
            }

            if (service.BaseAddress is not { IsAbsoluteUri: true }
                || (service.BaseAddress.Scheme != Uri.UriSchemeHttp
                    && service.BaseAddress.Scheme != Uri.UriSchemeHttps))
            {
                throw new InvalidOperationException(
                    $"ServiceClients:Services:BaseAddress для группы '{service.Group}' должен быть абсолютным HTTP(S) URI.");
            }

            if (service.Scopes.Length == 0 || service.Scopes.Any(string.IsNullOrWhiteSpace))
            {
                throw new InvalidOperationException(
                    $"ServiceClients:Services:Scopes для группы '{service.Group}' должен содержать хотя бы один scope.");
            }
        }
    }
}

/// <summary>
/// Настройки одного исходящего HTTP-клиента.
/// </summary>
public sealed class ServiceClientOptions
{
    /// <summary>
    /// Имя группы, используемое для сопоставления с прикладным контрактом.
    /// </summary>
    public string Group { get; init; } = string.Empty;

    /// <summary>
    /// Базовый адрес целевого сервиса.
    /// </summary>
    public Uri? BaseAddress { get; init; }

    /// <summary>
    /// OAuth scopes, запрашиваемые для вызовов сервиса.
    /// </summary>
    public string[] Scopes { get; init; } = [];
}
