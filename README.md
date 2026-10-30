# Vulpes plugins

Each plugin is its own .NET project in `Vulpes.Plugins.sln`. The Vulpes host does not contain plugin source. It lists the `.7z` assets published as [GitHub releases](https://github.com/techfox-au/vulpes-plugins/releases) of this repository and offers them as installs.

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

Publish `dist/microsoft-365-audit.7z` on a GitHub release. The dashboard picks it up under Manage → Plugins. The plugin id is `microsoft-365-audit` and its API is `/api/plugins/microsoft-365-audit`. The sidebar heading is the manifest section, shown in capitals, so this plugin reads **MICROSOFT 365 AUDIT**.
