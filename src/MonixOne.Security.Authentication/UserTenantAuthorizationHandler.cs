using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Options;

namespace MonixOne.Security.Authentication;

internal sealed class UserTenantAuthorizationHandler(
    IOptions<UserTenantAuthorizationOptions> options
) : IAuthorizationHandler
{
    public Task HandleAsync(AuthorizationHandlerContext context)
    {
        if (
            !context.User.Identities.Any(identity => identity.IsAuthenticated)
            || context.User.IsServiceIdentity()
        )
            return Task.CompletedTask;

        var tenantId = context.User.GetTenantId();
        if (
            tenantId is null
            || !options.Value.AllowedUserTenants.Contains(tenantId, StringComparer.Ordinal)
        )
            context.Fail();

        return Task.CompletedTask;
    }
}
