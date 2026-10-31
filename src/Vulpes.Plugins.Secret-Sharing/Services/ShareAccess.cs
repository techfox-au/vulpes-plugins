using System.Security.Claims;
using Vulpes.Sdk;

namespace Vulpes.Plugins.SecretSharing.Services;

/// <summary>Send is available to every dashboard role. Collect is analyst and admin only.</summary>
public static class ShareAccess
{
    public static bool CanCollect(ClaimsPrincipal user) =>
        user.IsInRole(DashboardRoles.Admin) || user.IsInRole(DashboardRoles.Analyst);

    public static bool CanCollect(IEnumerable<string> roles)
    {
        foreach (var role in roles)
        {
            if (role is DashboardRoles.Admin or DashboardRoles.Analyst)
            {
                return true;
            }
        }

        return false;
    }
}
