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

    /// <summary>Drops a token Graph has already rejected so the next call asks for a new one.</summary>
    void Invalidate();
}

public sealed class AzureIdentityTokenProvider : IGraphTokenProvider, IDisposable
{
    private readonly Func<TokenCredential> _createCredential;
    private readonly string _scope;
    private readonly IDisposable? _owned;
    private readonly Lock _gate = new();
    private TokenCredential _credential;
    private AccessToken _cached;

    public AzureIdentityTokenProvider(Func<TokenCredential> createCredential, string scope)
        : this(createCredential, scope, null)
    {
    }

    public AzureIdentityTokenProvider(CertificateCredential certificate, string scope)
        : this(certificate.Create, scope, certificate)
    {
    }

    private AzureIdentityTokenProvider(Func<TokenCredential> createCredential, string scope, IDisposable? owned)
    {
        ArgumentNullException.ThrowIfNull(createCredential);
        _createCredential = createCredential;
        _owned = owned;
        _credential = createCredential();
        _scope = scope;
    }

    public void Dispose() => _owned?.Dispose();

    public void Invalidate()
    {
        lock (_gate)
        {
            _cached = default;
            // ClientSecretCredential keeps its own MSAL cache, so a new instance is required
            // before the rejected token will actually be replaced.
            _credential = _createCredential();
        }
    }

    public async Task<string> GetTokenAsync(CancellationToken cancellationToken)
    {
        TokenCredential credential;
        lock (_gate)
        {
            if (!string.IsNullOrEmpty(_cached.Token) && _cached.ExpiresOn > DateTimeOffset.UtcNow.AddMinutes(5))
            {
                return _cached.Token;
            }

            credential = _credential;
        }

        var token = await credential.GetTokenAsync(new TokenRequestContext([_scope]), cancellationToken);
        lock (_gate)
        {
            _cached = token;
        }

        return token.Token;
    }
}

/// <summary>Creates token providers from stored (encrypted) tenant credentials.</summary>
public sealed class GraphCredentialFactory(IDataAtRestProtector data, ISecretProtector legacy)
{
    public IGraphTokenProvider Create(Tenant tenant)
    {
        ArgumentNullException.ThrowIfNull(tenant);
        var cloud = GraphCloud.For(tenant.Cloud);
        if (string.Equals(tenant.CredentialType, CredentialTypes.Certificate, StringComparison.Ordinal))
        {
            if (string.IsNullOrEmpty(tenant.ProtectedCertificate))
            {
                throw new InvalidOperationException("Tenant has no certificate configured.");
            }

            var pfx = Convert.FromBase64String(Open(tenant.ProtectedCertificate));
            var password = tenant.ProtectedCertificatePassword is null ? null : Open(tenant.ProtectedCertificatePassword);
            return new AzureIdentityTokenProvider(new CertificateCredential(() => LoadCertificate(pfx, password), tenant.TenantId, tenant.ClientId, cloud), cloud.Scope);
        }

        if (string.IsNullOrEmpty(tenant.ProtectedSecret))
        {
            throw new InvalidOperationException("Tenant has no client secret configured.");
        }

        var secret = Open(tenant.ProtectedSecret);
        return new AzureIdentityTokenProvider(
            () => new ClientSecretCredential(tenant.TenantId, tenant.ClientId, secret, new ClientSecretCredentialOptions { AuthorityHost = cloud.AuthorityHost }),
            cloud.Scope);
    }

    public static IGraphTokenProvider Create(string directoryId, EntraApplicationCredential application)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(directoryId);
        ArgumentNullException.ThrowIfNull(application);
        var cloud = GraphCloud.For(application.Cloud);
        if (string.Equals(application.CredentialType, CredentialTypes.Certificate, StringComparison.Ordinal))
        {
            if (string.IsNullOrEmpty(application.CertificatePfxBase64))
            {
                throw new InvalidOperationException("The Entra application has no certificate configured.");
            }

            var pfx = Convert.FromBase64String(application.CertificatePfxBase64);
            var password = application.CertificatePassword;
            return new AzureIdentityTokenProvider(new CertificateCredential(() => LoadCertificate(pfx, password), directoryId, application.ClientId, cloud), cloud.Scope);
        }

        if (string.IsNullOrEmpty(application.Secret))
        {
            throw new InvalidOperationException("The Entra application has no client secret configured.");
        }

        var secret = application.Secret;
        return new AzureIdentityTokenProvider(
            () => new ClientSecretCredential(directoryId, application.ClientId, secret, new ClientSecretCredentialOptions { AuthorityHost = cloud.AuthorityHost }),
            cloud.Scope);
    }

    private string Open(string stored) =>
        data.IsProtected(stored) ? data.Unprotect(stored)
        : stored.StartsWith("v1.", StringComparison.Ordinal) ? legacy.Unprotect(stored)
        : stored;

    private static X509Certificate2 LoadCertificate(byte[] pfx, string? password)
    {
        // EphemeralKeySet keeps the private key out of the Windows user store. macOS cannot load with that flag.
        var flags = OperatingSystem.IsMacOS() ? X509KeyStorageFlags.DefaultKeySet : X509KeyStorageFlags.EphemeralKeySet;
        return X509CertificateLoader.LoadPkcs12(pfx, password, flags);
    }
}

/// <summary>Loads the tenant certificate into memory only. A replaced certificate is disposed.</summary>
public sealed class CertificateCredential : IDisposable
{
    private readonly Func<X509Certificate2> _load;
    private readonly string _directoryId;
    private readonly string _clientId;
    private readonly GraphCloud _cloud;
    private X509Certificate2? _certificate;

    public CertificateCredential(Func<X509Certificate2> load, string directoryId, string clientId, GraphCloud cloud)
    {
        _load = load;
        _directoryId = directoryId;
        _clientId = clientId;
        _cloud = cloud;
    }

    public TokenCredential Create()
    {
        var next = _load();
        var previous = Interlocked.Exchange(ref _certificate, next);
        previous?.Dispose();
        return new ClientCertificateCredential(_directoryId, _clientId, next, new ClientCertificateCredentialOptions
        {
            AuthorityHost = _cloud.AuthorityHost,
            SendCertificateChain = true,
        });
    }

    public void Dispose() => Interlocked.Exchange(ref _certificate, null)?.Dispose();
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
public sealed class GraphClient : IDisposable
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

    public void Dispose()
    {
        if (_tokens is IDisposable disposable)
        {
            disposable.Dispose();
        }
    }

    public GraphCloud Cloud { get; }

    public int RequestCount { get; private set; }

    public int ThrottledCount { get; private set; }

    public Task<JsonDocument> GetAsync(string pathAndQuery, CancellationToken cancellationToken, bool beta = false) =>
        SendJsonAsync(HttpMethod.Get, Resolve(pathAndQuery, beta), null, cancellationToken);

    public Task<JsonDocument> PostAsync(string pathAndQuery, string jsonBody, CancellationToken cancellationToken, bool beta = false) =>
        SendJsonAsync(HttpMethod.Post, Resolve(pathAndQuery, beta), jsonBody, cancellationToken);

    /// <summary>Follows <c>@odata.nextLink</c> and yields every item of every page (bounded by <paramref name="maxPages"/>).</summary>
    public async IAsyncEnumerable<JsonElement> GetPagedAsync(string pathAndQuery, int maxPages, [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken cancellationToken, bool beta = false, Action<bool>? onCompleted = null, Action<string?>? onResume = null)
    {
        var next = Resolve(pathAndQuery, beta);
        var pages = 0;
        var complete = true;
        while (next is not null)
        {
            if (pages >= maxPages)
            {
                complete = false;
                onResume?.Invoke(next.AbsoluteUri);
                break;
            }

            pages++;
            // Remember this page so a caller that stops early can fetch it again. Duplicates are ignored downstream.
            onResume?.Invoke(next.AbsoluteUri);
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

        if (complete) onResume?.Invoke(null);
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
                    _tokens.Invalidate();
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
