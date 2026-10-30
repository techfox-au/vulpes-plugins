using System.Globalization;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using Azure.Core;
using Azure.Identity;
using Vulpes.Plugins.Microsoft365Audit.Data;
using Vulpes.Sdk;

namespace Vulpes.Plugins.Microsoft365Audit.Graph;

/// <summary>Cloud-specific endpoints.</summary>
public sealed record GraphCloud(string Name, Uri AuthorityHost, string GraphBase)
{
    public static readonly GraphCloud Global = new(Clouds.Global, AzureAuthorityHosts.AzurePublicCloud, "https://graph.microsoft.com");
    public static readonly GraphCloud UsGov = new(Clouds.UsGov, AzureAuthorityHosts.AzureGovernment, "https://graph.microsoft.us");

    public string Scope => GraphBase + "/.default";

    public static GraphCloud For(string? name) => string.Equals(name, Clouds.UsGov, StringComparison.OrdinalIgnoreCase) ? UsGov : Global;
}

/// <summary>Supplies bearer tokens for a tenant. Abstracted so tests can substitute a fake.</summary>
public interface IGraphTokenProvider
{
    Task<string> GetTokenAsync(CancellationToken cancellationToken);
}

public sealed class AzureIdentityTokenProvider : IGraphTokenProvider
{
    private readonly TokenCredential _credential;
    private readonly string _scope;
    private AccessToken _cached;

    public AzureIdentityTokenProvider(TokenCredential credential, string scope)
    {
        _credential = credential;
        _scope = scope;
    }

    public async Task<string> GetTokenAsync(CancellationToken cancellationToken)
    {
        if (!string.IsNullOrEmpty(_cached.Token) && _cached.ExpiresOn > DateTimeOffset.UtcNow.AddMinutes(5))
        {
            return _cached.Token;
        }

        _cached = await _credential.GetTokenAsync(new TokenRequestContext([_scope]), cancellationToken);
        return _cached.Token;
    }
}

/// <summary>Creates token providers from stored (encrypted) tenant credentials.</summary>
public sealed class GraphCredentialFactory(ISecretProtector protector)
{
    public IGraphTokenProvider Create(Tenant tenant)
    {
        ArgumentNullException.ThrowIfNull(tenant);
        var cloud = GraphCloud.For(tenant.Cloud);
        TokenCredential credential;
        if (string.Equals(tenant.CredentialType, CredentialTypes.Certificate, StringComparison.Ordinal))
        {
            if (string.IsNullOrEmpty(tenant.ProtectedCertificate))
            {
                throw new InvalidOperationException("Tenant has no certificate configured.");
            }

            var pfx = Convert.FromBase64String(protector.Unprotect(tenant.ProtectedCertificate));
            var password = tenant.ProtectedCertificatePassword is null ? null : protector.Unprotect(tenant.ProtectedCertificatePassword);
            var certificate = X509CertificateLoader.LoadPkcs12(pfx, password, X509KeyStorageFlags.DefaultKeySet);
            credential = new ClientCertificateCredential(tenant.TenantId, tenant.ClientId, certificate, new ClientCertificateCredentialOptions
            {
                AuthorityHost = cloud.AuthorityHost,
                SendCertificateChain = true,
            });
        }
        else
        {
            if (string.IsNullOrEmpty(tenant.ProtectedSecret))
            {
                throw new InvalidOperationException("Tenant has no client secret configured.");
            }

            credential = new ClientSecretCredential(tenant.TenantId, tenant.ClientId, protector.Unprotect(tenant.ProtectedSecret), new ClientSecretCredentialOptions
            {
                AuthorityHost = cloud.AuthorityHost,
            });
        }

        return new AzureIdentityTokenProvider(credential, cloud.Scope);
    }

    public static IGraphTokenProvider Create(string directoryId, EntraApplicationCredential application)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(directoryId);
        ArgumentNullException.ThrowIfNull(application);
        var cloud = GraphCloud.For(application.Cloud);
        TokenCredential credential;
        if (string.Equals(application.CredentialType, CredentialTypes.Certificate, StringComparison.Ordinal))
        {
            if (string.IsNullOrEmpty(application.CertificatePfxBase64))
            {
                throw new InvalidOperationException("The Entra application has no certificate configured.");
            }

            var pfx = Convert.FromBase64String(application.CertificatePfxBase64);
            var certificate = X509CertificateLoader.LoadPkcs12(pfx, application.CertificatePassword, X509KeyStorageFlags.DefaultKeySet);
            credential = new ClientCertificateCredential(directoryId, application.ClientId, certificate, new ClientCertificateCredentialOptions
            {
                AuthorityHost = cloud.AuthorityHost,
                SendCertificateChain = true,
            });
        }
        else
        {
            if (string.IsNullOrEmpty(application.Secret))
            {
                throw new InvalidOperationException("The Entra application has no client secret configured.");
            }

            credential = new ClientSecretCredential(directoryId, application.ClientId, application.Secret, new ClientSecretCredentialOptions
            {
                AuthorityHost = cloud.AuthorityHost,
            });
        }

        return new AzureIdentityTokenProvider(credential, cloud.Scope);
    }
}

public sealed class EntraTokenSource(IEntraApplication application) : IEntraTokenSource
{
    public async Task<string> GetTokenAsync(string directoryId, CancellationToken cancellationToken)
    {
        var app = await application.GetAsync(cancellationToken) ?? throw new InvalidOperationException("The Entra application is not configured.");
        return await GraphCredentialFactory.Create(directoryId, app).GetTokenAsync(cancellationToken);
    }
}

public sealed class GraphException : Exception
{
    public GraphException()
    {
    }

    public GraphException(string message) : base(message)
    {
    }

    public GraphException(string message, Exception innerException) : base(message, innerException)
    {
    }

    public HttpStatusCode? StatusCode { get; init; }

    public string? GraphErrorCode { get; init; }

    public bool IsForbidden => StatusCode is HttpStatusCode.Forbidden or HttpStatusCode.Unauthorized;
}

/// <summary>
/// Minimal Microsoft Graph REST client: bearer auth, JSON, <c>@odata.nextLink</c> paging and throttling
/// (429/503/504 with Retry-After, exponential backoff with jitter). Paths are built by the collectors from
/// constant templates and <see cref="Uri.EscapeDataString"/>-encoded values.
/// </summary>
public sealed class GraphClient
{
    private const int MaxRetries = 6;
    private static readonly TimeSpan MaxRetryDelay = TimeSpan.FromMinutes(5);

    private readonly HttpClient _http;
    private readonly IGraphTokenProvider _tokens;
    private readonly ILogger _logger;
    private readonly TimeProvider _time;

    public GraphClient(HttpClient http, IGraphTokenProvider tokens, GraphCloud cloud, ILogger logger, TimeProvider? timeProvider = null)
    {
        _http = http;
        _tokens = tokens;
        Cloud = cloud;
        _logger = logger;
        _time = timeProvider ?? TimeProvider.System;
    }

    public GraphCloud Cloud { get; }

    public int RequestCount { get; private set; }

    public int ThrottledCount { get; private set; }

    public Task<JsonDocument> GetAsync(string pathAndQuery, CancellationToken cancellationToken, bool beta = false) =>
        SendJsonAsync(HttpMethod.Get, Resolve(pathAndQuery, beta), null, cancellationToken);

    public Task<JsonDocument> PostAsync(string pathAndQuery, string jsonBody, CancellationToken cancellationToken, bool beta = false) =>
        SendJsonAsync(HttpMethod.Post, Resolve(pathAndQuery, beta), jsonBody, cancellationToken);

    /// <summary>Follows <c>@odata.nextLink</c> and yields every item of every page (bounded by <paramref name="maxPages"/>).</summary>
    public async IAsyncEnumerable<JsonElement> GetPagedAsync(string pathAndQuery, int maxPages, [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken cancellationToken, bool beta = false, Action<bool>? onCompleted = null)
    {
        var next = Resolve(pathAndQuery, beta);
        var pages = 0;
        var complete = true;
        while (next is not null)
        {
            if (pages++ >= maxPages)
            {
                complete = false;
                break;
            }

            using var document = await SendJsonAsync(HttpMethod.Get, next, null, cancellationToken);
            var root = document.RootElement;
            if (root.TryGetProperty("value", out var value) && value.ValueKind == JsonValueKind.Array)
            {
                foreach (var item in value.EnumerateArray())
                {
                    yield return item.Clone();
                }
            }

            next = root.TryGetProperty("@odata.nextLink", out var link) && link.ValueKind == JsonValueKind.String ? ValidateNextLink(link.GetString()) : null;
        }

        onCompleted?.Invoke(complete);
    }

    private Uri Resolve(string pathAndQuery, bool beta)
    {
        if (pathAndQuery.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
        {
            return ValidateNextLink(pathAndQuery) ?? throw new GraphException("Refusing to call a URL outside Microsoft Graph.");
        }

        var version = beta ? "beta" : "v1.0";
        return new Uri($"{Cloud.GraphBase}/{version}/{pathAndQuery.TrimStart('/')}", UriKind.Absolute);
    }

    /// <summary>Only follow continuation links that stay on the Graph host we started with.</summary>
    private Uri? ValidateNextLink(string? link)
    {
        if (string.IsNullOrEmpty(link) || !Uri.TryCreate(link, UriKind.Absolute, out var uri))
        {
            return null;
        }

        var graph = new Uri(Cloud.GraphBase);
        if (uri.Scheme != Uri.UriSchemeHttps || !string.Equals(uri.Host, graph.Host, StringComparison.OrdinalIgnoreCase))
        {
            _logger.LogWarning("Ignoring nextLink pointing outside Graph: {Host}", uri.Host);
            return null;
        }

        return uri;
    }

    private async Task<JsonDocument> SendJsonAsync(HttpMethod method, Uri uri, string? body, CancellationToken cancellationToken)
    {
        var attempt = 0;
        var refreshedToken = false;
        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();
            using var request = new HttpRequestMessage(method, uri);
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", await _tokens.GetTokenAsync(cancellationToken));
            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
            request.Headers.TryAddWithoutValidation("ConsistencyLevel", "eventual");
            if (body is not null)
            {
                request.Content = new StringContent(body, Encoding.UTF8, "application/json");
            }

            HttpResponseMessage response;
            try
            {
                RequestCount++;
                response = await _http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
            }
            catch (HttpRequestException ex) when (attempt < MaxRetries)
            {
                attempt++;
                var delay = Backoff(attempt);
                _logger.LogWarning(ex, "Graph request to {Path} failed ({Message}); retry {Attempt} in {Delay}s", uri.AbsolutePath, ex.Message, attempt, delay.TotalSeconds);
                await Task.Delay(delay, _time, cancellationToken);
                continue;
            }
            catch (TaskCanceledException) when (!cancellationToken.IsCancellationRequested && attempt < MaxRetries)
            {
                attempt++;
                await Task.Delay(Backoff(attempt), _time, cancellationToken);
                continue;
            }

            using (response)
            {
                if (response.StatusCode is HttpStatusCode.TooManyRequests or HttpStatusCode.ServiceUnavailable or HttpStatusCode.GatewayTimeout or HttpStatusCode.BadGateway)
                {
                    ThrottledCount++;
                    if (attempt >= MaxRetries)
                    {
                        throw new GraphException($"Graph throttled {uri.AbsolutePath} {MaxRetries} times; giving up.") { StatusCode = response.StatusCode };
                    }

                    attempt++;
                    var delay = RetryAfter(response) ?? Backoff(attempt);
                    _logger.LogInformation("Graph returned {Status} for {Path}; waiting {Delay}s (attempt {Attempt})", (int)response.StatusCode, uri.AbsolutePath, delay.TotalSeconds, attempt);
                    await Task.Delay(delay, _time, cancellationToken);
                    continue;
                }

                if (response.StatusCode == HttpStatusCode.Unauthorized && !refreshedToken)
                {
                    refreshedToken = true;
                    continue;
                }

                var content = await response.Content.ReadAsStringAsync(cancellationToken);
                if (!response.IsSuccessStatusCode)
                {
                    throw ParseError(response.StatusCode, uri, content);
                }

                return string.IsNullOrWhiteSpace(content) ? JsonDocument.Parse("{}") : JsonDocument.Parse(content);
            }
        }
    }

    private static TimeSpan? RetryAfter(HttpResponseMessage response)
    {
        var header = response.Headers.RetryAfter;
        if (header is null)
        {
            return null;
        }

        TimeSpan? delay = header.Delta ?? (header.Date is { } date ? date - DateTimeOffset.UtcNow : null);
        if (delay is null || delay.Value <= TimeSpan.Zero)
        {
            return TimeSpan.FromSeconds(2);
        }

        return delay.Value > MaxRetryDelay ? MaxRetryDelay : delay.Value;
    }

    private static TimeSpan Backoff(int attempt)
    {
        var seconds = Math.Min(Math.Pow(2, attempt), 120);
        var jitter = Random.Shared.NextDouble() * seconds * 0.25;
        return TimeSpan.FromSeconds(seconds + jitter);
    }

    private static GraphException ParseError(HttpStatusCode status, Uri uri, string content)
    {
        string? code = null;
        string? message = null;
        try
        {
            using var doc = JsonDocument.Parse(content);
            if (doc.RootElement.TryGetProperty("error", out var error))
            {
                code = error.TryGetProperty("code", out var c) ? c.GetString() : null;
                message = error.TryGetProperty("message", out var m) ? m.GetString() : null;
            }
        }
        catch (JsonException)
        {
            // Non-JSON error body.
        }

        var text = string.Create(CultureInfo.InvariantCulture, $"Graph {uri.AbsolutePath} returned {(int)status} {status}{(code is null ? string.Empty : $" ({code})")}{(message is null ? string.Empty : ": " + message)}");
        return new GraphException(text.Length <= 1000 ? text : text[..1000]) { StatusCode = status, GraphErrorCode = code };
    }
}

/// <summary>Builds a <see cref="GraphClient"/> per tenant (HttpClient from the host factory).</summary>
public class GraphClientFactory(IHttpClientFactory httpClientFactory, GraphCredentialFactory credentials, ILoggerFactory loggerFactory, TimeProvider timeProvider)
{
    public const string HttpClientName = "vc-audit-graph";

    public virtual GraphClient Create(Tenant tenant)
    {
        ArgumentNullException.ThrowIfNull(tenant);
        var http = httpClientFactory.CreateClient(HttpClientName);
        http.Timeout = TimeSpan.FromSeconds(100);
        return new GraphClient(http, credentials.Create(tenant), GraphCloud.For(tenant.Cloud), loggerFactory.CreateLogger("Vulpes.Audit.Graph"), timeProvider);
    }
}

/// <summary>Helpers for OData query construction.</summary>
public static class OData
{
    public static string Timestamp(DateTimeOffset value) => value.UtcDateTime.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", CultureInfo.InvariantCulture);

    /// <summary>Escapes a string literal for use inside an OData <c>$filter</c> (single quotes doubled) and URL-encodes the result.</summary>
    public static string Literal(string value) => Uri.EscapeDataString("'" + value.Replace("'", "''", StringComparison.Ordinal) + "'");
}
