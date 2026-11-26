using System.Net;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

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
                    var scan = context.RequestServices.GetRequiredService<ShareScanGuard>();
                    var feature = context.Features.Get<Microsoft.AspNetCore.Http.Features.IHttpMaxRequestBodySizeFeature>();
                    var trailingSlash = (context.Request.Path.Value ?? "").EndsWith('/');
                    // A lockout must leave the solved ticket in place. CollectUpload answers 429
                    // before it would consume, and a new ticket cannot be issued until the window clears.
                    // A trailing slash is not the upload route, so it keeps the small cap and does not burn a proof.
                    if (trailingSlash || scan.IsFailureBudgetExceeded(BudgetClientKey(context), out _))
                    {
                        if (feature is { IsReadOnly: false }) feature.MaxRequestBodySize = PowService.SmallBodyBytes;
                    }
                    else
                    {
                        var pow = context.RequestServices.GetRequiredService<PowService>();
                        PowService.ReadFromHeaders(context.Request.Headers, out var challenge, out var nonce, out var hash);
                        var clientTime = context.Request.Headers[PowService.HeaderTime].ToString();
                        var id = UploadId(context.Request.Path);
                        var browser = Vulpes.Sdk.PowBrowser.Current(context);
                        var proven = challenge is not null && nonce is not null && id is not null
                            && pow.TryConsume("collect", id, challenge, nonce, hash, browser, clientTime) is null;
                        if (feature is { IsReadOnly: false })
                        {
                            feature.MaxRequestBodySize = proven ? PowService.LargeBodyBytes : PowService.SmallBodyBytes;
                        }

                        if (proven) context.Items[PowService.HttpContextPowConsumed] = true;
                    }
                }

                await nextMiddleware();
            });
            next(app);
        };

    /// <summary>
    /// The gate runs before forwarded headers, so RemoteIpAddress is still the proxy.
    /// Failure counts are stored under the address the middleware will keep. That walk
    /// stops after ForwardLimit hops (the default is 1) and does not skip every trusted proxy.
    /// </summary>
    private static string BudgetClientKey(HttpContext http)
    {
        var remote = http.Connection.RemoteIpAddress;
        var options = http.RequestServices.GetService<IOptions<ForwardedHeadersOptions>>()?.Value;
        if (remote is null || options is null || !IsTrustedProxy(remote, options))
        {
            return ShareScanGuard.ClientKey(http);
        }

        var parts = http.Request.Headers.GetCommaSeparatedValues(options.ForwardedForHeaderName);
        if (parts.Length == 0)
        {
            return ShareScanGuard.ClientKey(http);
        }

        var entryCount = parts.Length;
        if (options.ForwardLimit is int limit && entryCount > limit)
        {
            entryCount = limit;
        }

        var current = remote;
        var checkKnown = options.KnownProxies.Count > 0 || options.KnownIPNetworks.Count > 0;
        for (var i = 0; i < entryCount; i++)
        {
            if (checkKnown && !IsTrustedProxy(current, options))
            {
                break;
            }

            var text = parts[parts.Length - 1 - i];
            if (!TryParseForwarded(text, out var address))
            {
                if (!string.IsNullOrWhiteSpace(text))
                {
                    break;
                }

                continue;
            }

            current = address;
        }

        return current.ToString();
    }

    /// <summary>
    /// Same trust check as <see cref="Microsoft.AspNetCore.HttpOverrides.ForwardedHeadersMiddleware"/>.
    /// A mapped known-proxy entry does not match a plain IPv4 peer, so the gate does not walk
    /// X-Forwarded-For when the middleware will leave the peer in place.
    /// </summary>
    private static bool IsTrustedProxy(IPAddress address, ForwardedHeadersOptions options)
    {
        if (address.IsIPv4MappedToIPv6 && IsTrustedProxy(address.MapToIPv4(), options))
        {
            return true;
        }

        foreach (var proxy in options.KnownProxies)
        {
            if (proxy.Equals(address))
            {
                return true;
            }
        }

        foreach (var network in options.KnownIPNetworks)
        {
            if (network.Contains(address))
            {
                return true;
            }
        }

        return false;
    }

    private static bool TryParseForwarded(string text, out IPAddress address)
    {
        var value = text.Trim().Trim('"');
        if (value.Length >= 2 && value[0] == '[')
        {
            var end = value.IndexOf(']');
            if (end > 1)
            {
                value = value[1..end];
            }
        }

        var colon = value.LastIndexOf(':');
        if (colon > 0 && value.IndexOf(':') == colon)
        {
            value = value[..colon];
        }

        if (!IPAddress.TryParse(value, out var parsed) || parsed is null)
        {
            address = IPAddress.None;
            return false;
        }

        address = parsed;
        return true;
    }

    private static bool IsCollectUpload(PathString path)
    {
        var parts = Parts(path);
        return parts.Length == 6
            && parts[0].Equals("api", StringComparison.OrdinalIgnoreCase)
            && parts[1].Equals("plugins", StringComparison.OrdinalIgnoreCase)
            && parts[2].Equals("secret-sharing", StringComparison.OrdinalIgnoreCase)
            && parts[3].Equals("public", StringComparison.OrdinalIgnoreCase)
            && parts[4].Equals("collects", StringComparison.OrdinalIgnoreCase);
    }

    private static string? UploadId(PathString path)
    {
        var parts = Parts(path);
        return parts.Length == 6 ? Uri.UnescapeDataString(parts[5]) : null;
    }

    private static string[] Parts(PathString path) =>
        (path.Value ?? "").Trim().TrimEnd('/').Split('/', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
}
