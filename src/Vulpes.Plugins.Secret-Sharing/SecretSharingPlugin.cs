using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Vulpes.Plugins.SecretSharing.Data;
using Vulpes.Plugins.SecretSharing.Endpoints;
using Vulpes.Plugins.SecretSharing.Services;
using Vulpes.Sdk;

namespace Vulpes.Plugins.SecretSharing;

public sealed class SecretSharingPlugin : IPlugin
{
    public string Id => "secret-sharing";

    public void ConfigureServices(IServiceCollection services, IPluginContext context)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(context);
        services.AddSingleton(new ShareDatabase(context.DatabasePath));
        services.AddSingleton<PowService>();
        services.AddSingleton<ShareScanGuard>();
        services.AddSingleton<ShareStore>();
        services.AddSingleton<IIpRestrictedSecretQuery>(sp => sp.GetRequiredService<ShareStore>());
        services.AddSingleton<Microsoft.AspNetCore.Hosting.IStartupFilter, CollectUploadGate>();
        services.AddHostedService<ShareExpiryService>();
        services.AddSingleton<NotificationMail>();
        services.AddSingleton<IUserSecretReset, SecretReset>();
        services.AddSingleton<IMcpToolSource>(sp => new SecretSharingMcp(
            sp.GetRequiredService<ShareStore>(),
            sp.GetRequiredService<IHostEmail>(),
            sp.GetRequiredService<IClientIpCapability>()));
    }

    public void MapEndpoints(IEndpointRouteBuilder endpoints, IPluginContext context)
    {
        ArgumentNullException.ThrowIfNull(endpoints);
        ShareEndpoints.Map(endpoints);
    }

    public Task InitializeAsync(IServiceProvider services, IPluginContext context, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(context);
        cancellationToken.ThrowIfCancellationRequested();
        return Task.CompletedTask;
    }
}
