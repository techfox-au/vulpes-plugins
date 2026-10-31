# Vulpes plugins

Each plugin is its own .NET project in `Vulpes.Plugins.sln`. The Vulpes host does not contain plugin source. Release packages are the `.7z` files in `latest/`, listed in the clear-signed `latest/manifest`. The host reads that manifest and offers the listed packages as installs.

Check this repo out next to the host repo:

```
~/vulpes
~/vulpes-plugins
```

Plugins compile against `Vulpes.Sdk` from the host checkout. The path defaults to `../vulpes`. Override it with `/p:VulpesRoot=/path/to/vulpes/`.

## Projects

| Project | What it is |
| --- | --- |
| `src/Vulpes.Plugins.Microsoft-365-Audit` | Microsoft 365 audit collection (Graph, Purview, Defender, Identity Protection, Secure Score). |
| `tests/Vulpes.Plugins.Microsoft-365-Audit.Tests` | Tests for that plugin. They also build the host, so the host checkout has to be present. |

Add another plugin by adding a class library to this solution. Keep `EnableDynamicLoading` set, reference `$(VulpesRoot)src/Vulpes.Sdk/Vulpes.Sdk.csproj`, and ship a `plugin.json` plus `wwwroot`. Authoring details are in the host repo at `docs/plugins.md`.

## Build

```bash
dotnet build
dotnet test
```

Pack a release asset from here, using the packer in the host repo:

```bash
dotnet publish src/Vulpes.Plugins.Microsoft-365-Audit -c Release -o out/audit
dotnet publish ../vulpes/src/Vulpes.Host -c Release -o out/host
dotnet run --project ../vulpes/tools/Vulpes.PluginPacker -- \
  --plugin-dir out/audit --host-dir out/host --rid-prefix linux --output dist/microsoft-365-audit.7z
```

`./build.sh` publishes every plugin, packs each `.7z` into `latest/`, and clear-signs `latest/manifest`. The host repo must be checked out next to this one, or set `VULPES_ROOT`. The manifest starts with `hmac_key:`. Each later line is `name.7z:<hmac-sha512>:<version>`. A `latest/<package name without .7z>.txt` file, when present, is the description shown on Manage → Plugins.

The dashboard installs a package listed in that signed manifest. The Microsoft 365 plugin id is `microsoft-365-audit` and its API is `/api/plugins/microsoft-365-audit`. The sidebar heading is the manifest section, shown in capitals, so this plugin reads **MICROSOFT 365 AUDIT**.
