namespace MonixOne.Security.Authentication;

/// <summary>
/// Настройки локальной проверки access token, выпущенного доверенным Authorization Server.
/// </summary>
public sealed class PlatformAuthenticationOptions
{
    /// <summary>
    /// Стандартное имя секции конфигурации.
    /// </summary>
    public const string SectionName = "Identity";

    /// <summary>
    /// Канонический issuer Authorization Server, используемый для discovery, JWKS и проверки claim <c>iss</c>.
    /// </summary>
    public string Authority { get; init; } = string.Empty;

    /// <summary>
    /// OAuth resource, который должен присутствовать в claim <c>aud</c> принимаемого access token.
    /// </summary>
    public string Audience { get; init; } = string.Empty;

    /// <summary>
    /// Требует HTTPS при загрузке discovery и JWKS. Отключение допускается только в окружении Local.
    /// </summary>
    public bool RequireHttpsMetadata { get; init; } = true;

    /// <summary>
    /// Допустимое отклонение времени при проверке <c>nbf</c> и <c>exp</c>, в секундах.
    /// </summary>
    public int ClockSkewSeconds { get; init; } = 30;
}
