using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;

namespace Vulpes.Plugins.SecretSharing.Services;

/// <summary>
/// Burns the collect-upload proof from headers before the body is read, and only then allows a large body.
/// </summary>
public sealed class CollectUploadGate : IStartupFilter
{
    public Action<IApplicationBuilder> Configure(Action<IApplicationBuilder> next)
        => app =>
        {
            app.Use(async (context, nextMiddleware) =>
            {
                if (HttpMethods.IsPost(context.Request.Method) && IsCollectUpload(context.Request.Path))
                {
                    var pow = context.RequestServices.GetRequiredService<PowService>();
                    var store = context.RequestServices.GetRequiredService<ShareStore>();
                    PowService.ReadFromHeaders(context.Request.Headers, out var challenge, out var nonce, out var hash);
                    var id = UploadId(context.Request.Path);
                    var meta = id is null ? null : store.CollectMeta(id);
                    var open = meta is not null && meta.Status == "waiting";
                    var browser = Vulpes.Sdk.PowBrowser.Current(context);
                    var proven = challenge is not null && nonce is not null && id is not null && open
                        && pow.TryConsume("collect", id, challenge, nonce, hash, browser) is null;
                    var feature = context.Features.Get<Microsoft.AspNetCore.Http.Features.IHttpMaxRequestBodySizeFeature>();
                    if (feature is { IsReadOnly: false })
                    {
                        feature.MaxRequestBodySize = proven ? PowService.LargeBodyBytes : PowService.SmallBodyBytes;
                    }

                    if (proven) context.Items[PowService.HttpContextPowConsumed] = true;
                }

                await nextMiddleware();
            });
            next(app);
        };

    private static bool IsCollectUpload(PathString path)
    {
        var parts = (path.Value ?? "").Split('/', StringSplitOptions.RemoveEmptyEntries);
        return parts.Length == 6
            && parts[0].Equals("api", StringComparison.OrdinalIgnoreCase)
            && parts[1].Equals("plugins", StringComparison.OrdinalIgnoreCase)
            && parts[2].Equals("secret-sharing", StringComparison.OrdinalIgnoreCase)
            && parts[3].Equals("public", StringComparison.OrdinalIgnoreCase)
            && parts[4].Equals("collects", StringComparison.OrdinalIgnoreCase);
    }

    private static string? UploadId(PathString path)
    {
        var parts = (path.Value ?? "").Split('/', StringSplitOptions.RemoveEmptyEntries);
        return parts.Length == 6 ? Uri.UnescapeDataString(parts[5]) : null;
    }
}
