using System.Text;
using System.Text.Json;
using Vulpes.Plugins.SecretSharing;
using Vulpes.Plugins.SecretSharing.Data;
using Vulpes.Plugins.SecretSharing.Services;
using Vulpes.Sdk;
using Xunit;

namespace Vulpes.Plugins.SecretSharing.Tests;

public sealed class BotSendTests
{
    [Theory]
    [InlineData(
        "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4",
        "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c",
        "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552")]
    [InlineData(
        "4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d",
        "e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493",
        "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957")]
    public void X25519_matches_the_bouncy_castle_scalar_vectors(string scalar, string point, string expected)
    {
        var shared = X25519.ScalarMult(Convert.FromHexString(scalar), Convert.FromHexString(point));
        Assert.Equal(expected, Convert.ToHexString(shared).ToLowerInvariant());
    }

    [Fact]
    public void X25519_matches_the_bouncy_castle_ecdh_vector()
    {
        var alice = Convert.FromHexString("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        var bob = Convert.FromHexString("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
        var alicePublic = X25519.ScalarMultBase(alice);
        var bobPublic = X25519.ScalarMultBase(bob);
        Assert.Equal("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a", Convert.ToHexString(alicePublic).ToLowerInvariant());
        Assert.Equal("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f", Convert.ToHexString(bobPublic).ToLowerInvariant());
        var shared = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742";
        Assert.Equal(shared, Convert.ToHexString(X25519.ScalarMult(alice, bobPublic)).ToLowerInvariant());
        Assert.Equal(shared, Convert.ToHexString(X25519.ScalarMult(bob, alicePublic)).ToLowerInvariant());
    }

    [Fact]
    public void X25519_matches_the_bouncy_castle_iterated_vector()
    {
        var k = new byte[32];
        var u = new byte[32];
        k[0] = 9;
        u[0] = 9;
        for (var i = 1; i <= 1000; i++)
        {
            var next = X25519.ScalarMult(k, u);
            u = k;
            k = next;
            if (i == 1)
            {
                Assert.Equal("422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079", Convert.ToHexString(k).ToLowerInvariant());
            }
        }

        Assert.Equal("684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51", Convert.ToHexString(k).ToLowerInvariant());
    }

    [Fact]
    public async Task A_bot_send_opens_with_the_link_and_the_note_opens_only_with_its_key()
    {
        var directory = Directory.CreateTempSubdirectory("bot-send");
        try
        {
            var store = new ShareStore(new ShareDatabase(Path.Combine(directory.FullName, "secrets.db")));
            var mcp = new SecretSharingMcp(store, new OriginEmail("https://secrets.example"), new IpCap(true));
            var key = new byte[32];
            key[0] = 7;
            var caller = new McpCaller("token-1", key);
            var created = await mcp.CallAsync("create_secret", Args("""{"text":"correct horse","label":"Wifi","privateNote":"router cupboard","oneTime":true,"disclosureAccepted":true}"""), caller, CancellationToken.None);
            Assert.False(created.IsError, created.Text);
            using var document = JsonDocument.Parse(created.StructuredJson!);
            var link = document.RootElement.GetProperty("link").GetString()!;
            Assert.StartsWith("https://secrets.example/send?id=", link, StringComparison.Ordinal);
            var hash = link[link.IndexOf('#')..];
            var secret = Base64Url.Decode(hash["#sk=".Length..]);
            var id = document.RootElement.GetProperty("id").GetString()!;
            var listed = await mcp.CallAsync("list_secrets", default, caller, CancellationToken.None);
            Assert.Contains("router cupboard", listed.Text, StringComparison.Ordinal);
            Assert.Contains("Wifi", listed.Text, StringComparison.Ordinal);
            Assert.DoesNotContain("correct horse", listed.Text, StringComparison.Ordinal);
            var row = store.TakeSend(id);
            Assert.NotNull(row);
            var plain = SendCipher.Decrypt(new SendWire(row.Ciphertext, row.Iv, row.WrappedKey, row.EphemeralPublicKey), secret);
            Assert.Equal("correct horse", Encoding.UTF8.GetString(plain));
            Assert.DoesNotContain("collect", mcp.Tools.Select(tool => tool.Name), StringComparer.Ordinal);
            Assert.DoesNotContain("#sk=", listed.Text, StringComparison.Ordinal);
            Assert.DoesNotContain("\"link\"", listed.Text, StringComparison.Ordinal);
            AssertLinkIsNotStored(directory.FullName);

            var other = new byte[32];
            other[0] = 9;
            var hidden = await mcp.CallAsync("list_secrets", default, new McpCaller("token-1", other), CancellationToken.None);
            Assert.DoesNotContain("router cupboard", hidden.Text, StringComparison.Ordinal);
        }
        finally
        {
            directory.Delete(true);
        }
    }

    [Fact]
    public async Task A_bot_send_can_use_a_password_a_file_and_an_ip_allow_list()
    {
        var directory = Directory.CreateTempSubdirectory("bot-send-options");
        try
        {
            var store = new ShareStore(new ShareDatabase(Path.Combine(directory.FullName, "secrets.db")));
            var mcp = new SecretSharingMcp(store, new OriginEmail("https://secrets.example"), new IpCap(true));
            var caller = new McpCaller("token-1", new byte[32]);
            var file = Convert.ToBase64String("hello file"u8.ToArray());
            var created = await mcp.CallAsync(
                "create_secret",
                Args("{\"fileBase64\":\"" + file + "\",\"filename\":\"note.txt\",\"contentType\":\"text/plain\",\"password\":\"correct horse\",\"allowedIps\":\"203.0.113.10\",\"disclosureAccepted\":true}"),
                caller,
                CancellationToken.None);
            Assert.False(created.IsError, created.Text);
            using var document = JsonDocument.Parse(created.StructuredJson!);
            Assert.True(document.RootElement.GetProperty("passwordProtected").GetBoolean());
            var link = document.RootElement.GetProperty("link").GetString()!;
            var package = Encoding.UTF8.GetString(Base64Url.Decode(link[(link.IndexOf("#sk=", StringComparison.Ordinal) + 4)..]));
            var secret = SendCipher.UnwrapSecretKey(package, "correct horse");
            var row = store.TakeSend(document.RootElement.GetProperty("id").GetString()!);
            Assert.Equal("note.txt", row!.Filename);
            Assert.Equal("hello file", Encoding.UTF8.GetString(SendCipher.Decrypt(new SendWire(row.Ciphertext, row.Iv, row.WrappedKey, row.EphemeralPublicKey), secret)));
            Assert.Equal("203.0.113.10", store.AllowedCidr(document.RootElement.GetProperty("id").GetString()!));

            var denied = await new SecretSharingMcp(store, new OriginEmail("https://secrets.example"), new IpCap(false))
                .CallAsync("create_secret", Args("""{"text":"x","allowedIps":"203.0.113.10","disclosureAccepted":true}"""), caller, CancellationToken.None);
            Assert.True(denied.IsError);
            Assert.Contains("IP restrictions are unavailable", denied.Text, StringComparison.Ordinal);
        }
        finally
        {
            directory.Delete(true);
        }
    }

    [Fact]
    public async Task A_bot_cannot_create_a_send_until_the_user_accepts_the_disclosure()
    {
        var directory = Directory.CreateTempSubdirectory("bot-send-disclosure");
        try
        {
            var store = new ShareStore(new ShareDatabase(Path.Combine(directory.FullName, "secrets.db")));
            var mcp = new SecretSharingMcp(store, new OriginEmail("https://secrets.example"), new IpCap(true));
            var create = mcp.Tools.Single(tool => tool.Name == "create_secret");
            Assert.Contains("Any secret you submit will be shared with SpaceXSI.", create.Description, StringComparison.Ordinal);
            Assert.Contains("explicit approval", create.Description, StringComparison.Ordinal);
            Assert.Contains("Any secret you submit will be shared with SpaceXSI.", mcp.Instructions, StringComparison.Ordinal);

            var caller = new McpCaller("token-1", new byte[32]);
            var blocked = await mcp.CallAsync("create_secret", Args("""{"text":"not yet"}"""), caller, CancellationToken.None);
            Assert.True(blocked.IsError);
            Assert.Contains("Any secret you submit will be shared with SpaceXSI.", blocked.Text, StringComparison.Ordinal);
            Assert.Contains("explicit approval", blocked.Text, StringComparison.Ordinal);

            var declined = await mcp.CallAsync("create_secret", Args("""{"text":"still no","disclosureAccepted":false}"""), caller, CancellationToken.None);
            Assert.True(declined.IsError);
            var listed = await mcp.CallAsync("list_secrets", default, caller, CancellationToken.None);
            Assert.DoesNotContain("not yet", listed.Text, StringComparison.Ordinal);
            Assert.DoesNotContain("still no", listed.Text, StringComparison.Ordinal);
        }
        finally
        {
            directory.Delete(true);
        }
    }

    [Fact]
    public async Task A_bot_does_not_email_a_link_until_the_address_is_confirmed()
    {
        var directory = Directory.CreateTempSubdirectory("bot-send-confirm");
        try
        {
            var store = new ShareStore(new ShareDatabase(Path.Combine(directory.FullName, "secrets.db")));
            var mail = new OriginEmail("https://secrets.example") { Accept = true };
            var mcp = new SecretSharingMcp(store, mail, new IpCap(true));
            var blocked = await mcp.CallAsync("create_secret", Args("""{"text":"hold","emailTo":"person@example.test","disclosureAccepted":true}"""), new McpCaller("token-1", new byte[32]), CancellationToken.None);
            Assert.True(blocked.IsError);
            Assert.Contains("person@example.test", blocked.Text, StringComparison.Ordinal);
            Assert.Contains("confirm", blocked.Text, StringComparison.OrdinalIgnoreCase);
            Assert.Null(mail.LastText);
            var listed = await mcp.CallAsync("list_secrets", default, new McpCaller("token-1", new byte[32]), CancellationToken.None);
            using var listedJson = JsonDocument.Parse(listed.StructuredJson!);
            Assert.Equal(0, listedJson.RootElement.GetProperty("secrets").GetArrayLength());
        }
        finally
        {
            directory.Delete(true);
        }
    }

    [Fact]
    public async Task Secret_text_uses_the_same_length_cap_as_a_person()
    {
        var directory = Directory.CreateTempSubdirectory("bot-send-length");
        try
        {
            var store = new ShareStore(new ShareDatabase(Path.Combine(directory.FullName, "secrets.db")));
            var mcp = new SecretSharingMcp(store, new OriginEmail("https://secrets.example"), new IpCap(true));
            var text = new string('a', 1_000_001);
            var blocked = await mcp.CallAsync("create_secret", Args("{\"text\":\"" + text + "\",\"disclosureAccepted\":true}"), new McpCaller("token-1", new byte[32]), CancellationToken.None);
            Assert.True(blocked.IsError);
            Assert.Contains("1000000", blocked.Text, StringComparison.Ordinal);
        }
        finally
        {
            directory.Delete(true);
        }
    }

    [Fact]
    public async Task A_bot_link_can_be_emailed_and_is_still_not_stored()
    {
        var directory = Directory.CreateTempSubdirectory("bot-send-mail");
        try
        {
            var store = new ShareStore(new ShareDatabase(Path.Combine(directory.FullName, "secrets.db")));
            var mail = new OriginEmail("https://secrets.example") { Accept = true };
            var mcp = new SecretSharingMcp(store, mail, new IpCap(true));
            var created = await mcp.CallAsync("create_secret", Args("""{"text":"mailbox secret","emailTo":"person@example.test","disclosureAccepted":true,"emailConfirmed":true}"""), new McpCaller("token-1", new byte[32]), CancellationToken.None);
            Assert.False(created.IsError, created.Text);
            using var document = JsonDocument.Parse(created.StructuredJson!);
            var link = document.RootElement.GetProperty("link").GetString()!;
            Assert.Contains("#sk=", link, StringComparison.Ordinal);
            Assert.True(document.RootElement.GetProperty("emailed").GetBoolean());
            Assert.Equal(link, mail.LastText!.Split('\n', StringSplitOptions.RemoveEmptyEntries)[^1]);
            var listed = await mcp.CallAsync("list_secrets", default, new McpCaller("token-1", new byte[32]), CancellationToken.None);
            Assert.DoesNotContain("#sk=", listed.Text, StringComparison.Ordinal);
            AssertLinkIsNotStored(directory.FullName);
        }
        finally
        {
            directory.Delete(true);
        }
    }

    private static void AssertLinkIsNotStored(string directory)
    {
        var marker = "#sk="u8;
        foreach (var file in Directory.GetFiles(directory))
        {
            var bytes = File.ReadAllBytes(file);
            for (var i = 0; i <= bytes.Length - marker.Length; i++)
            {
                if (bytes.AsSpan(i, marker.Length).SequenceEqual(marker))
                {
                    Assert.Fail($"The link was written to {Path.GetFileName(file)}.");
                }
            }
        }
    }

    private static JsonElement Args(string json)
    {
        using var document = JsonDocument.Parse(json);
        return document.RootElement.Clone();
    }

    private sealed class IpCap(bool enabled) : IClientIpCapability
    {
        public bool IpRestrictionsEnabled => enabled;
    }

    private sealed class OriginEmail(string origin) : IHostEmail
    {
        public string PublicOrigin => origin;

        public bool Accept { get; init; }

        public string? LastText { get; private set; }

        public Task<bool> TrySendAsync(string to, string subject, string text, string html, CancellationToken cancellationToken = default)
        {
            LastText = text;
            return Task.FromResult(Accept);
        }

        public Task<bool> TrySendAsync(string to, string subject, string text, string html, IReadOnlyList<HostEmailAttachment> attachments, CancellationToken cancellationToken = default) => Task.FromResult(false);

        public Task<bool> TrySendAsync(string to, string subject, string text, string html, IReadOnlyList<HostEmailAttachment> attachments, string? fromName, string? fromAddress, CancellationToken cancellationToken = default) => Task.FromResult(false);

        public Task<bool> TrySendAsync(string to, string subject, string text, string html, IReadOnlyList<HostEmailAttachment> attachments, string? fromName, string? fromAddress, IReadOnlyList<string>? cc, CancellationToken cancellationToken = default) => Task.FromResult(false);
    }
}
