using System.Net;
using System.Net.Sockets;
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
    internal const string FilenameHeader = "X-Sendit-Filename";

    internal const int MaxFilenameLength = 200;
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
                    var routeId = RouteId(context.Request.Path);
                    // The header is Latin-1. The page percent-encodes the UTF-8 filename so a name such as
                    // 秘密.txt can be sent. The length is the decoded name, not the encoded header.
                    var nameTooLong = FilenameTooLong(context.Request.Headers[FilenameHeader].ToString());
                    // A lockout must leave the solved ticket in place. CollectUpload answers 429
                    // before it would consume, and a new ticket cannot be issued until the window clears.
                    // A trailing slash is not the upload route, so it keeps the small cap and does not burn a proof.
                    // An empty segment is not the upload route. Routing keeps a space in the id, so the proof is
                    // spent only for that same segment. Trimming it would burn the real collect's proof.
                    if (trailingSlash || routeId is null || nameTooLong || scan.IsFailureBudgetExceeded(BudgetClientKey(context), out _))
                    {
                        if (feature is { IsReadOnly: false }) feature.MaxRequestBodySize = PowService.SmallBodyBytes;
                    }
                    else
                    {
                        var pow = context.RequestServices.GetRequiredService<PowService>();
                        PowService.ReadFromHeaders(context.Request.Headers, out var challenge, out var nonce, out var hash);
                        var clientTime = context.Request.Headers[PowService.HeaderTime].ToString();
                        var id = routeId;
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
    /// The host drops a link-local zone only after this gate, so the peer is unscoped first.
    /// </summary>
    internal static string BudgetClientKey(HttpContext http)
    {
        var remote = UnscopePeer(http.Connection.RemoteIpAddress);
        var options = http.RequestServices.GetService<IOptions<ForwardedHeadersOptions>>()?.Value;
        if (remote is null || options is null || !IsTrustedProxy(remote, options))
        {
            return remote?.ToString() ?? ShareScanGuard.ClientKey(http);
        }

        var parts = http.Request.Headers.GetCommaSeparatedValues(options.ForwardedForHeaderName);
        if (parts.Length == 0)
        {
            return remote.ToString();
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
    /// A zone index is not part of the address. fe80::1%12 and fe80::1 are the same peer.
    /// An address that is already unscoped, including IPv4, stays the same instance.
    /// </summary>
    private static IPAddress? UnscopePeer(IPAddress? address)
    {
        if (address is null || address.AddressFamily != AddressFamily.InterNetworkV6 || address.ScopeId == 0)
        {
            return address;
        }

        return new IPAddress(address.GetAddressBytes());
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
        // Do not trim. Forwarded-headers parses the same token with IPEndPoint.TryParse, which keeps a trailing space.
        var value = text;
        if (IPEndPoint.TryParse(value, out var endpoint))
        {
            address = endpoint.Address;
            return true;
        }

        // A broken port, such as 203.0.113.50:80a, is not an address the forwarded-headers middleware will keep.
        if (value.Contains(':') && !(value.StartsWith('[') && value.EndsWith(']')))
        {
            address = IPAddress.None;
            return false;
        }

        if (!IPAddress.TryParse(value, out var parsed) || parsed is null)
        {
            address = IPAddress.None;
            return false;
        }

        address = parsed;
        return true;
    }

    /// <summary>
    /// A header longer than <see cref="MaxFilenameLength"/> after UTF-8 percent-decoding is rejected before the proof is spent.
    /// A header that is not valid percent-encoding is treated the same way. An unencoded Latin-1 name is used as written.
    /// </summary>
    internal static bool FilenameTooLong(string header)
    {
        if (!TryDecodeFilename(header, out var name))
        {
            return true;
        }

        return FileNameText(name).Length > MaxFilenameLength;
    }

    /// <summary>Removes characters that are whitespace for either the page or .NET, including a mark in the middle of the name.</summary>
    internal static string FileNameText(string value) =>
        value.Replace("\uFEFF", "", StringComparison.Ordinal).Replace("\u0085", "", StringComparison.Ordinal).Trim();

    private static bool TryDecodeFilename(string header, out string name)
    {
        if (header.IndexOf('%') < 0)
        {
            name = header;
            return true;
        }

        try
        {
            name = Uri.UnescapeDataString(header);
            return true;
        }
        catch (UriFormatException)
        {
            name = "";
            return false;
        }
    }

    private static bool IsCollectUpload(PathString path)
    {
        // Do not trim the id. A whitespace-only id is still the upload route, and an empty segment stays one too.
        var parts = (path.Value ?? "").TrimEnd('/').Split('/');
        return parts.Length >= 7
            && parts[1].Equals("api", StringComparison.OrdinalIgnoreCase)
            && parts[2].Equals("plugins", StringComparison.OrdinalIgnoreCase)
            && parts[3].Equals("secret-sharing", StringComparison.OrdinalIgnoreCase)
            && parts[4].Equals("public", StringComparison.OrdinalIgnoreCase)
            && parts[5].Equals("collects", StringComparison.OrdinalIgnoreCase)
            && parts.Skip(6).Any(part => part.Length > 0);
    }

    /// <summary>The id the route binds. A space stays. An empty segment, including a doubled slash, is not an id.</summary>
    internal static string? RouteId(PathString path)
    {
        var value = (path.Value ?? "").TrimEnd('/');
        var parts = value.Split('/');
        if (parts.Length != 7)
        {
            return null;
        }

        for (var i = 1; i < parts.Length; i++)
        {
            if (parts[i].Length == 0)
            {
                return null;
            }
        }

        // The path is already decoded once. A second unescape would turn abc%20 into "abc " and spend a different id's proof.
        return parts[6];
    }

    /// <summary>A trailing slash is not the upload the handler should accept. The id segment itself can contain spaces.</summary>
    internal static bool HandlerConsumesProof(PathString path) => !(path.Value ?? "").EndsWith('/');
}
