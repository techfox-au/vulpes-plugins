# Making a Vulpes plugin

This file is the instruction set for people and for coding agents. Follow it when adding or changing a plugin in this repository.

Plugin source lives here. The host lives in the sibling checkout `../vulpes` (override with `/p:VulpesRoot=` or `VULPES_ROOT`). The host installs a packed `.7z`. It does not compile this solution.

The host repository has a shorter overview at `docs/plugins.md`. When that overview and this file disagree, follow this file and the interfaces in `../vulpes/src/Vulpes.Sdk`.

Two plugins are already here. Microsoft 365 Audit collects logs into Elasticsearch and renders dashboard pages. Secret Sharing keeps its own SQLite database and serves anonymous recipient pages. Copy the shape of the one that matches the work. Read its `plugin.json`, project file, and `IPlugin` class before adding a third.

## Rules

- Compile only against `Vulpes.Sdk`. Leave `Vulpes.Host` types out of the plugin project. A test project may reference the host.
- Ship exactly one public, non-abstract `IPlugin` in the entry assembly. It needs a public parameterless constructor. `IPlugin.Id` and `plugin.json` `id` are the same string.
- Read the SDK source before calling a host service. If the capability is not an interface in `Vulpes.Sdk`, it is not available to the plugin.
- Keep package versions in `Directory.Packages.props`. A `PackageReference` in a project file has no `Version` attribute.
- Set `<Version>` in the plugin project to the same semantic version as `plugin.json`. `Directory.Build.props` would otherwise stamp the assembly `0.1.0`.
- Warnings are errors, nullable is on, and NuGet audit fails the build on known-vulnerable packages. Fix the warning. Leave the `NoWarn` list in `Directory.Build.props` as it is.
- Store secrets with the protectors below. Leave passwords, tokens, and key material out of logs, exceptions, and JSON responses.
- `./build.sh` publishes every plugin. It replaces a `latest/*.7z` only when the files that would be packed differ from that archive's `files.sha256`, and clear-signs `latest/manifest` only then. Run it only when cutting a release. It needs `gpg`, `python3`, and the release key.
- The dashboard image includes PowerShell 7 as `pwsh`. It is the Alpine community package for that image's architecture, both amd64 and arm64. `dotnet` on `PATH` remains the ASP.NET runtime.

## Create the project

Pick an id that matches `^[a-z][a-z0-9-]{1,31}$`. These names are reserved: `incoming`, `host`, `core`, `api`, `auth`, `app`, `admin`.

Use that id in `plugin.json`. Name the folder and assembly `Vulpes.Plugins.` plus a Pascal-case form, with hyphens between words, matching the two existing plugins. Set `RootNamespace` to the same name with the hyphens removed, because a namespace cannot contain a hyphen.

```xml
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <Version>1.0.0</Version>
    <Description>Vulpes plugin: one sentence.</Description>
    <EnableDynamicLoading>true</EnableDynamicLoading>
    <RootNamespace>Vulpes.Plugins.Example</RootNamespace>
    <AssemblyName>Vulpes.Plugins.Example</AssemblyName>
  </PropertyGroup>

  <ItemGroup>
    <FrameworkReference Include="Microsoft.AspNetCore.App" />
  </ItemGroup>

  <ItemGroup>
    <ProjectReference Include="$(VulpesRoot)src/Vulpes.Sdk/Vulpes.Sdk.csproj" />
  </ItemGroup>

  <ItemGroup>
    <None Include="plugin.json" CopyToOutputDirectory="PreserveNewest" />
    <None Include="wwwroot\**\*" CopyToOutputDirectory="PreserveNewest" />
  </ItemGroup>
</Project>
```

`EnableDynamicLoading` writes the `deps.json` the host loader needs. Add the project to `Vulpes.Plugins.sln`:

```bash
dotnet sln Vulpes.Plugins.sln add src/Vulpes.Plugins.Example/Vulpes.Plugins.Example.csproj
```

A new package also needs a line in `Directory.Packages.props`. Host-shared packages (EF Core SQLite, the Elasticsearch client, SharpCompress, MailKit) may be referenced. The packer strips any assembly the host already ships, plus `Vulpes.Sdk`, when `./build.sh` passes the published host directory. Everything else is private and is loaded from the plugin folder. Keep `Microsoft.EntityFrameworkCore.Design` in a `Debug`-only item group with `PrivateAssets` so it never ships.

## plugin.json

```json
{
  "id": "example",
  "name": "Example",
  "version": "1.0.0",
  "description": "One or two sentences, at most 500 characters.",
  "entryAssembly": "Vulpes.Plugins.Example.dll",
  "sdkVersion": "1.0.0",
  "nav": [
    { "page": "home", "title": "Home", "icon": "list", "roles": ["Viewer", "Analyst", "Admin"], "order": 10, "section": "Example" }
  ],
  "requirements": [
    "What an administrator must have in place before the plugin can work."
  ]
}
```

`entryAssembly` is the file name of the DLL, with no directory. `sdkVersion` is a semantic version whose major component equals `SdkInfo.Major` in the SDK (currently 1). `version` is `digits.digits.digits` with an optional prerelease suffix.

`nav` has at most 50 entries. Each `page` is unique and matches `^[a-z][a-z0-9-]{0,63}$`. `title` is at most 60 characters. `icon` and `section` are at most 40. `roles` is a non-empty subset of `Admin`, `Analyst`, and `Viewer`. `section` is the sidebar heading; the shell shows it in capitals. `requirements` is documentation only: at most 100 strings, each at most 200 characters.

Icons are symbol ids in the host sprite `wwwroot/assets/img/icons.svg`: `home`, `bell`, `user`, `users`, `puzzle`, `plug`, `settings`, `list`, `terminal`, `chart`, `login`, `directory`, `activity`, `shield`, `exclamation-octagon`, `warning`, `building`, `pulse`, `funnel`, `lock`, `key`, `sparkles`, `sun`, `moon`, `logout`, `x`, `check`, `search`, `refresh`, `plus`, `trash`, `edit`, `copy`, `download`, `upload`, `external`, `info`, `dot`, `mail`, `send-up`, `send-down`, `play`, `eye`.

Also add `latest/Vulpes.Plugins.Example.txt`. The file name is the assembly name. The host shows that text on Manage → Plugins next to the release. Write a few plain sentences, the way `latest/Vulpes.Plugins.Microsoft-365-Audit.txt` does. `plugin.json` `description` is a separate, shorter field.

## The C# entry point

```csharp
public sealed class ExamplePlugin : IPlugin
{
    public string Id => "example";

    public void ConfigureServices(IServiceCollection services, IPluginContext context)
    {
        services.AddDbContext<ExampleDbContext>(o => o.UseSqlite($"Data Source={context.DatabasePath}"));
        services.AddHostedService<ExampleWorker>();
    }

    public void MapEndpoints(IEndpointRouteBuilder endpoints, IPluginContext context)
    {
        endpoints.MapGet("/items", List).RequireAuthorization(Policies.Viewer);
        endpoints.MapPost("/items", Create).RequireAuthorization(Policies.Admin);
    }

    public async Task InitializeAsync(IServiceProvider services, IPluginContext context, CancellationToken cancellationToken)
    {
        await using var scope = services.CreateAsyncScope();
        await scope.ServiceProvider.GetRequiredService<ExampleDbContext>().Database.MigrateAsync(cancellationToken);
    }
}
```

`ConfigureServices` runs while the host is still building its container. `MapEndpoints` receives a group rooted at `/api/plugins/{id}`. That group already requires an authenticated user and the API rate limit. Tighten a route with `RequireAuthorization(Policies.Admin)`, `Policies.Analyst`, or `Policies.Viewer`. `InitializeAsync` runs once during startup, after the host database and search schema are ready, and before the process serves traffic. Migrate the plugin database there.

`IPluginContext` gives `Manifest`, `InstallDirectory` (read-only package files), `DataDirectory` (writable, kept across upgrades), `DatabasePath` (`{DataDirectory}/{id}.db`), `Configuration` (the `Plugins:Settings:{id}` section), and `ApiPrefix`.

An upgrade replaces the `pkg/` directory only. The data directory and SQLite file stay. Change the schema with EF Core migrations. Uninstall keeps that data unless an administrator chooses to purge it.

## Services the host provides

Inject these. They are registered before `ConfigureServices`.

| Interface | Use it for |
| --- | --- |
| `IEventPipeline` | Publish `SecurityEvent` records. Indexing is idempotent. Per-document failures are counted, not thrown. |
| `IEventSearch` | Search and aggregate the plugin's own sources. Field names are checked against the catalog. `IsAvailable` is false when no search backend is configured. |
| `IAlertFieldCatalog` | Read the registered sources and fields. |
| `ISecretProtector` | Encrypt a credential the server must later decrypt (a client secret, a token). The stored form starts with the protector's version prefix. |
| `IDataAtRestProtector` | Seal a value the browser already encrypted, so a copy of the database is not the key. `IsProtected` detects an envelope. `Unprotect` returns an unsealed value unchanged. |
| `IHostAuditLog` | Write an administrative audit entry. Background work passes `actor` itself, for example `system:example`. |
| `IHostEmail` | Send mail through the host transport. `TrySendAsync` returns false when mail is not configured. `PublicOrigin` is the dashboard origin with no trailing slash. |
| `IHttpClientFactory` | Outbound HTTP. |
| `TimeProvider` | Clocks and delays. |
| `IPowPolicy` | Live proof-of-work difficulty (1–28) and ticket lifetime in seconds (30–600). Difficulty is never zero. |
| `IClientIpCapability` | `IpRestrictionsEnabled` is false when the server cannot see a public visitor address. A restrictive allow-list then denies access. |
| `IUserRoles` | Roles of a user who is not the caller. An unknown or inactive user has none. |
| `ITenantDirectory` | The shared list of consented Entra directories. |
| `IEntraApplication` | The one Entra application credential, shared by every tenant. |
| `IEntraTokenSource` | An app-only Graph token for one directory. |

`ISecretProtector` and `IDataAtRestProtector` solve different problems. Use the first for a secret the server created or was given in plaintext. Use the second for ciphertext the browser already produced. Leave payload ciphertext sealed only by the client key.

## Interfaces the plugin may implement

Register the implementation in `ConfigureServices`. The host discovers every registration.

- `IIndexSchemaContributor` declares event sources. A source name matches `^[a-z][a-z0-9-]{1,31}$` and is unique within the plugin. `EventStorageMode.DataStream` is append-only. `EventStorageMode.Index` upserts by id, for state that changes. List filterable fields on `EventSourceDefinition.Fields` so alert rules and explorers can use them.
- `ISourceAvailability` marks a source as not collectable, for example when a licence cannot produce it.
- `IGraphPermissionSource` lists Graph application permissions the shared Entra app needs. Each entry is a `GraphAccess` name, purpose, and optional source.
- `ITenantConnectionTester` checks that the shared app can read this plugin's data in one tenant.
- `IUserSecretReset` runs when an administrator sets a temporary password and the old user data key is destroyed.
- `IIpRestrictedSecretQuery` answers whether this plugin still has an unexpired secret with an IP allow-list.

A `SecurityEvent` sets `PluginId`, `Source`, `RecordId`, `TenantId`, and `Timestamp`. The host document id is derived from tenant, source, and record. Fill the envelope fields that apply (`Category`, `Action`, `Outcome`, `UserName`, `SourceIp`, and the rest on the type). Put extra keywords in `Labels` and the upstream record in `Data`.

## Pages

For each `nav` entry, add `wwwroot/pages/<page>.html` and `wwwroot/js/<page>.js`. The shell fetches the HTML fragment and then imports the module. The page URL is `/p/{id}/{page}`.

The HTML fragment contains markup only. The content security policy is `script-src 'self'`, so an inline script, an inline event handler, or a style attribute will not run. Put behaviour in the module. Import a sibling file with a relative URL.

```javascript
export async function mount(el, ctx) {
  ctx.setTitle(['Home']);
  const rows = await ctx.api.get(`${ctx.plugin.apiBase}/items`);
  el.append(ctx.ui.table({ columns: [{ key: 'name', label: 'Name' }], rows }));
}

export function unmount() {}
```

`ctx` provides:

- `api.get`, `api.post`, `api.put`, `api.patch`, `api.delete`, `api.upload`, and `api.qs`. Unsafe methods send the CSRF header. A signed-in page that receives 401 goes to `/login`.
- `ui`: `h`, `append`, `clear`, `icon`, `badge`, `fmt`, `table`, `kv`, `jsonView`, `empty`, `spinner`, `toast`, `panelNote`, `pageNote`, `drawer`, `modal`, `dropdown`, `filePicker`, `formValues`, `setBusy`, `errorMessage`, `copyToClipboard`, `columnChart`, `barList`, `valueAt`.
- `user`, `hasRole(role)`, `navigate`, `query`, `setTitle`, `refreshNav`, `refreshChrome`.
- `plugin.id`, `plugin.apiBase` (`/api/plugins/{id}`), `plugin.assetBase` (`/plugins/{id}`).

Files under `wwwroot/` other than `public/` require a signed-in user. They are served at `/plugins/{id}/...`.

## Anonymous pages and routes

Put browser files that must load with no session under `wwwroot/public/`. They are served at `/plugins/{id}/public/...` and are cached as private static files. Those files contain no secrets.

The host rewrites `/send`, `/upload`, `/collect`, and `/plugins/secret-sharing/send` for Secret Sharing only. A new plugin does not get those aliases.

A route that must answer without a session calls `.AllowAnonymous()` on that route. Keep the handler safe for an anonymous caller: prove possession of a link secret before returning ciphertext, and return the same response for a missing record and a destroyed one when revealing the difference would help a scan.

## Tests

Add `tests/Vulpes.Plugins.<Name>.Tests` as an xUnit project, mark it `IsTestProject`, and add it to the solution. Reference the plugin project. Reference `$(VulpesRoot)src/Vulpes.Host/Vulpes.Host.csproj` when a test has to boot the host. Package references used by tests (`xunit`, `Microsoft.NET.Test.Sdk`, `xunit.runner.visualstudio`, `Microsoft.AspNetCore.Mvc.Testing`) are already in `Directory.Packages.props`.

Cover the behaviour a caller can observe: authorization, persistence, and the failure cases that must look identical. Use `InternalsVisibleTo` when a test has to reach an internal type.

```bash
dotnet test
```

The host checkout has to be present. Tests that boot the host also build it.

## Release package

`./build.sh` publishes each project under `src/` that has a `plugin.json`. A `.7z` is named after the entry assembly (`Vulpes.Plugins.Example.dll` becomes `Vulpes.Plugins.Example.7z`). If `latest/` already has that archive and its `files.sha256` matches the files that would be packed, the archive is left in place. Otherwise it is packed again. `latest/manifest` is rewritten and clear-signed only when a package was packed or removed. The manifest's first line is `hmac_key:`. Each later line is `name.7z:<hmac-sha512>:<version>`. The dashboard installs only a package whose HMAC is on that signed manifest.

The host records the SHA-256 of the entry DLL at install and checks it on every load. Replacing the DLL in an installed `pkg/` directory makes the plugin fail to load. Ship the change as a new package from the signed manifest, then restart the dashboard.

To pack one plugin without rewriting the manifest:

```bash
dotnet publish src/Vulpes.Plugins.Example -c Release -o out/example
dotnet publish ../vulpes/src/Vulpes.Host -c Release -o out/host
dotnet run --project ../vulpes/tools/Vulpes.PluginPacker -- \
  --plugin-dir out/example --host-dir out/host --rid-prefix linux \
  --output dist/Vulpes.Plugins.Example.7z
```

The install gate is the HMAC in the clear-signed `latest/manifest`.

## Checklist

1. Project file, `plugin.json`, one `IPlugin`, and `wwwroot` pages for every `nav` entry.
2. `Version` in the project matches `plugin.json`. `sdkVersion` major matches the SDK.
3. New packages are pinned in `Directory.Packages.props`.
4. Both projects are in `Vulpes.Plugins.sln`.
5. `latest/<AssemblyName>.txt` describes the release.
6. `dotnet test` passes.
7. A release, and only a release, is packed with `./build.sh`.
