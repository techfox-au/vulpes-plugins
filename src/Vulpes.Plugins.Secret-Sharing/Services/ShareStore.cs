using System.Security.Cryptography;
using Microsoft.Data.Sqlite;
using Vulpes.Plugins.SecretSharing.Data;

namespace Vulpes.Plugins.SecretSharing.Services;

public sealed class ShareStore(ShareDatabase database)
{
    /// <summary>Base64url length of Sendit's 60 MiB × 1.05 ciphertext cap. A 40 MiB file encrypts to about 56 million characters.</summary>
    public const int MaxCipherChars = 88_080_384;

    public string? GetWrappedUserDataKey(string userId)
    {
        using var conn = database.Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT Wrapped FROM user_data_keys WHERE UserId = @id";
        cmd.Parameters.AddWithValue("@id", userId);
        return cmd.ExecuteScalar() as string;
    }

    public IReadOnlyList<UserDataKeyWrap> ListWraps(string userId)
    {
        using var conn = database.Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT Kind, CredentialId, Wrapped FROM user_data_key_wraps WHERE UserId = @id";
        cmd.Parameters.AddWithValue("@id", userId);
        using var reader = cmd.ExecuteReader();
        var rows = new List<UserDataKeyWrap>();
        while (reader.Read())
        {
            rows.Add(new UserDataKeyWrap(reader.GetString(0), reader.GetString(1), reader.GetString(2)));
        }

        return rows;
    }

    /// <summary>Stores one wrap. Returns true when this is the user's first package.</summary>
    public bool UpsertWrap(string userId, string kind, string credentialId, string wrapped)
    {
        using var conn = database.Open();
        using var count = conn.CreateCommand();
        count.CommandText = "SELECT (SELECT COUNT(*) FROM user_data_key_wraps WHERE UserId = @id) + (SELECT COUNT(*) FROM user_data_keys WHERE UserId = @id)";
        count.Parameters.AddWithValue("@id", userId);
        var first = Convert.ToInt32(count.ExecuteScalar(), System.Globalization.CultureInfo.InvariantCulture) == 0;
        using var cmd = conn.CreateCommand();
        cmd.CommandText = """
            INSERT INTO user_data_key_wraps (UserId, Kind, CredentialId, Wrapped, CreatedAt)
            VALUES (@id, @kind, @cred, @wrapped, @at)
            ON CONFLICT(UserId, Kind, CredentialId) DO UPDATE SET Wrapped = excluded.Wrapped
            """;
        cmd.Parameters.AddWithValue("@id", userId);
        cmd.Parameters.AddWithValue("@kind", kind);
        cmd.Parameters.AddWithValue("@cred", credentialId);
        cmd.Parameters.AddWithValue("@wrapped", wrapped);
        cmd.Parameters.AddWithValue("@at", DateTimeOffset.UtcNow.ToString("O"));
        cmd.ExecuteNonQuery();
        return first;
    }

    public bool DeleteWrap(string userId, string kind, string credentialId)
    {
        using var conn = database.Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "DELETE FROM user_data_key_wraps WHERE UserId = @id AND Kind = @kind AND CredentialId = @cred";
        cmd.Parameters.AddWithValue("@id", userId);
        cmd.Parameters.AddWithValue("@kind", kind);
        cmd.Parameters.AddWithValue("@cred", credentialId);
        return cmd.ExecuteNonQuery() == 1;
    }

    public NotificationPrefs GetNotifications(string userId)
    {
        using var conn = database.Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT Email, NotifyCollectReady, NotifySendOpened FROM notification_prefs WHERE UserId = @id";
        cmd.Parameters.AddWithValue("@id", userId);
        using var reader = cmd.ExecuteReader();
        if (!reader.Read())
        {
            return new NotificationPrefs("", false, false);
        }

        return new NotificationPrefs(reader.GetString(0), reader.GetInt32(1) == 1, reader.GetInt32(2) == 1);
    }

    public void SaveNotifications(string userId, string email, bool collectReady, bool sendOpened)
    {
        using var conn = database.Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = """
            INSERT INTO notification_prefs (UserId, Email, NotifyCollectReady, NotifySendOpened)
            VALUES (@id, @email, @collect, @send)
            ON CONFLICT(UserId) DO UPDATE SET Email = excluded.Email, NotifyCollectReady = excluded.NotifyCollectReady, NotifySendOpened = excluded.NotifySendOpened
            """;
        cmd.Parameters.AddWithValue("@id", userId);
        cmd.Parameters.AddWithValue("@email", email);
        cmd.Parameters.AddWithValue("@collect", collectReady ? 1 : 0);
        cmd.Parameters.AddWithValue("@send", sendOpened ? 1 : 0);
        cmd.ExecuteNonQuery();
    }

    public void RememberEmail(string userId, string email)
    {
        using var conn = database.Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = """
            UPDATE notification_prefs SET Email = @email WHERE UserId = @id AND Email <> @email
            """;
        cmd.Parameters.AddWithValue("@id", userId);
        cmd.Parameters.AddWithValue("@email", email);
        cmd.ExecuteNonQuery();
    }

    public NotifyTarget? CollectReadyTarget(string collectId) => Target(collect: true, collectId);

    public NotifyTarget? SendOpenedTarget(string sendId) => Target(collect: false, sendId);

    public bool TryAllowNotifyEmail(string email, out TimeSpan retryAfter)
    {
        email = email.Trim().ToLowerInvariant();
        retryAfter = TimeSpan.Zero;
        using var conn = database.Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT SendCount, LastSendMs FROM notify_email_budget WHERE Email = @email";
        cmd.Parameters.AddWithValue("@email", email);
        using var reader = cmd.ExecuteReader();
        if (!reader.Read())
        {
            return true;
        }

        var count = reader.GetInt32(0);
        if (count <= 0)
        {
            return true;
        }

        var min = count < 24 ? TimeSpan.FromMilliseconds(2500) : TimeSpan.FromSeconds(15);
        var elapsed = TimeSpan.FromMilliseconds(Math.Max(0, DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() - reader.GetInt64(1)));
        if (elapsed >= min)
        {
            return true;
        }

        retryAfter = min - elapsed;
        return false;
    }

    public void NoteNotifyEmailSent(string email)
    {
        email = email.Trim().ToLowerInvariant();
        using var conn = database.Open();
        using var read = conn.CreateCommand();
        read.CommandText = "SELECT SendCount FROM notify_email_budget WHERE Email = @email";
        read.Parameters.AddWithValue("@email", email);
        var existing = read.ExecuteScalar();
        var count = existing is null or DBNull ? 1 : Convert.ToInt32(existing, System.Globalization.CultureInfo.InvariantCulture) + 1;
        using var cmd = conn.CreateCommand();
        cmd.CommandText = """
            INSERT INTO notify_email_budget (Email, SendCount, LastSendMs)
            VALUES (@email, @count, @at)
            ON CONFLICT(Email) DO UPDATE SET SendCount = excluded.SendCount, LastSendMs = excluded.LastSendMs
            """;
        cmd.Parameters.AddWithValue("@email", email);
        cmd.Parameters.AddWithValue("@count", count);
        cmd.Parameters.AddWithValue("@at", DateTimeOffset.UtcNow.ToUnixTimeMilliseconds());
        cmd.ExecuteNonQuery();
    }

    private NotifyTarget? Target(bool collect, string id)
    {
        using var conn = database.Open();
        using var cmd = conn.CreateCommand();
        if (collect)
        {
            cmd.CommandText = """
                SELECT c.OwnerUserId, p.Email
                FROM collects c
                INNER JOIN notification_prefs p ON p.UserId = c.OwnerUserId
                WHERE c.Id = @id AND p.NotifyCollectReady = 1 AND length(p.Email) > 0
                """;
        }
        else
        {
            cmd.CommandText = """
                SELECT s.OwnerUserId, p.Email
                FROM secrets s
                INNER JOIN notification_prefs p ON p.UserId = s.OwnerUserId
                WHERE s.Id = @id AND p.NotifySendOpened = 1 AND length(p.Email) > 0
                """;
        }
        cmd.Parameters.AddWithValue("@id", id);
        using var reader = cmd.ExecuteReader();
        return reader.Read() ? new NotifyTarget(reader.GetString(0), reader.GetString(1)) : null;
    }

    public (int Sends, int Collects) ResetUser(string userId)
    {
        using var conn = database.Open();
        using var tx = conn.BeginTransaction();
        using (var cmd = conn.CreateCommand())
        {
            cmd.Transaction = tx;
            cmd.CommandText = "DELETE FROM user_data_key_wraps WHERE UserId = @id";
            cmd.Parameters.AddWithValue("@id", userId);
            cmd.ExecuteNonQuery();
        }

        using (var cmd = conn.CreateCommand())
        {
            cmd.Transaction = tx;
            cmd.CommandText = "DELETE FROM user_data_keys WHERE UserId = @id";
            cmd.Parameters.AddWithValue("@id", userId);
            cmd.ExecuteNonQuery();
        }

        int sends;
        using (var cmd = conn.CreateCommand())
        {
            cmd.Transaction = tx;
            cmd.CommandText = "DELETE FROM secrets WHERE OwnerUserId = @id";
            cmd.Parameters.AddWithValue("@id", userId);
            sends = cmd.ExecuteNonQuery();
        }

        int collects;
        using (var cmd = conn.CreateCommand())
        {
            cmd.Transaction = tx;
            cmd.CommandText = "DELETE FROM collects WHERE OwnerUserId = @id";
            cmd.Parameters.AddWithValue("@id", userId);
            collects = cmd.ExecuteNonQuery();
        }

        tx.Commit();
        return (sends, collects);
    }

    public string CreateSend(string ownerId, SendInput input)
    {
        var id = NewId();
        var now = DateTimeOffset.UtcNow;
        using var conn = database.Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = """
            INSERT INTO secrets (Id, OwnerUserId, EncryptedLabel, Ciphertext, Iv, WrappedKey, EphemeralPublicKey, ContentType, Filename, OneTime, CreatedAt, ExpiresAt, PrivateNoteCiphertext, MaxAccessCount, PasswordProtected, HideTextByDefault, AllowedCidr, RecipientLabel)
            VALUES (@id, @owner, @label, @ct, @iv, @wk, @eph, @type, @file, @once, @created, @expires, @note, @max, @pw, @hide, @cidr, @recipient)
            """;
        BindCommon(cmd, id, ownerId, input, now);
        cmd.ExecuteNonQuery();
        return id;
    }

    public string CreateCollect(string ownerId, CollectInput input)
    {
        var id = NewId();
        var now = DateTimeOffset.UtcNow;
        using var conn = database.Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = """
            INSERT INTO collects (Id, OwnerUserId, EncryptedLabel, PublicKey, OwnerPrivateKeyProtected, OneTime, CreatedAt, ExpiresAt, PrivateNoteCiphertext, MaxAccessCount, PasswordProtected, HideTextByDefault, PublicLabel)
            VALUES (@id, @owner, @label, @pk, @sk, @once, @created, @expires, @note, @max, @pw, @hide, @publicLabel)
            """;
        cmd.Parameters.AddWithValue("@id", id);
        cmd.Parameters.AddWithValue("@owner", ownerId);
        cmd.Parameters.AddWithValue("@label", (object?)input.EncryptedLabel ?? DBNull.Value);
        cmd.Parameters.AddWithValue("@pk", input.PublicKey);
        cmd.Parameters.AddWithValue("@sk", (object?)input.OwnerPrivateKeyProtected ?? DBNull.Value);
        cmd.Parameters.AddWithValue("@once", input.OneTime ? 1 : 0);
        cmd.Parameters.AddWithValue("@created", now.ToString("O"));
        cmd.Parameters.AddWithValue("@expires", now.AddMinutes(input.ExpiresInMinutes).ToString("O"));
        cmd.Parameters.AddWithValue("@note", (object?)input.PrivateNoteCiphertext ?? DBNull.Value);
        cmd.Parameters.AddWithValue("@max", input.OneTime ? DBNull.Value : (object?)input.MaxAccessCount ?? DBNull.Value);
        cmd.Parameters.AddWithValue("@pw", input.PasswordProtected ? 1 : 0);
        cmd.Parameters.AddWithValue("@hide", input.HideTextByDefault ? 1 : 0);
        cmd.Parameters.AddWithValue("@publicLabel", (object?)input.PublicLabel ?? DBNull.Value);
        cmd.ExecuteNonQuery();
        return id;
    }

    public int PurgeExpired()
    {
        using var conn = database.Open();
        var removed = 0;
        foreach (var id in GoneSecretIds(conn)) removed += DeleteSecret(conn, id);
        foreach (var id in GoneCollectIds(conn)) removed += DeleteCollectRow(conn, id);
        return removed;
    }

    private static List<string> GoneSecretIds(SqliteConnection conn)
    {
        using var sel = conn.CreateCommand();
        sel.CommandText = "SELECT Id, ExpiresAt, ConsumedAt, OneTime, MaxAccessCount, AccessCount FROM secrets";
        return ReadGoneIds(sel);
    }

    private static List<string> GoneCollectIds(SqliteConnection conn)
    {
        using var sel = conn.CreateCommand();
        sel.CommandText = "SELECT Id, ExpiresAt, ConsumedAt, OneTime, MaxAccessCount, AccessCount FROM collects";
        return ReadGoneIds(sel);
    }

    private static List<string> ReadGoneIds(SqliteCommand sel)
    {
        using var reader = sel.ExecuteReader();
        var ids = new List<string>();
        var now = DateTimeOffset.UtcNow;
        while (reader.Read())
        {
            var expires = reader.GetString(1);
            var consumed = !reader.IsDBNull(2);
            var oneTime = reader.GetInt32(3) == 1;
            int? max = reader.IsDBNull(4) ? null : reader.GetInt32(4);
            var access = reader.IsDBNull(5) ? 0 : reader.GetInt32(5);
            var atLimit = !oneTime && max is int cap && access >= cap;
            var past = !DateTimeOffset.TryParse(expires, System.Globalization.CultureInfo.InvariantCulture, System.Globalization.DateTimeStyles.RoundtripKind, out var exp) || exp <= now;
            if (consumed || atLimit || past) ids.Add(reader.GetString(0));
        }

        return ids;
    }

    private static int DeleteSecret(SqliteConnection conn, string id)
    {
        using var del = conn.CreateCommand();
        del.CommandText = "DELETE FROM secrets WHERE Id = @id";
        del.Parameters.AddWithValue("@id", id);
        return del.ExecuteNonQuery();
    }

    private static int DeleteCollectRow(SqliteConnection conn, string id)
    {
        using var del = conn.CreateCommand();
        del.CommandText = "DELETE FROM collects WHERE Id = @id";
        del.Parameters.AddWithValue("@id", id);
        return del.ExecuteNonQuery();
    }

    public IReadOnlyList<HomeItem> List(string ownerId)
    {
        PurgeExpired();
        var now = DateTimeOffset.UtcNow;
        var items = new List<HomeItem>();
        using var conn = database.Open();
        using (var cmd = conn.CreateCommand())
        {
            cmd.CommandText = """
                SELECT Id, EncryptedLabel, OneTime, CreatedAt, ExpiresAt, ConsumedAt, AccessCount, MaxAccessCount, PasswordProtected, PrivateNoteCiphertext, AllowedCidr
                FROM secrets WHERE OwnerUserId = @owner ORDER BY CreatedAt DESC LIMIT 100
                """;
            cmd.Parameters.AddWithValue("@owner", ownerId);
            using var reader = cmd.ExecuteReader();
            while (reader.Read())
            {
                var cidr = reader.IsDBNull(10) ? null : reader.GetString(10);
                var item = ReadHome(reader, "send", uploaded: true, now) with
                {
                    PrivateNoteCiphertext = reader.IsDBNull(9) ? null : reader.GetString(9),
                    IpRestricted = !string.IsNullOrWhiteSpace(cidr) && !string.Equals(cidr.Trim(), "*", StringComparison.Ordinal),
                };
                if (item.Status is not ("expired" or "consumed")) items.Add(item);
            }
        }

        using (var cmd = conn.CreateCommand())
        {
            cmd.CommandText = """
                SELECT Id, EncryptedLabel, OneTime, CreatedAt, ExpiresAt, ConsumedAt, AccessCount, MaxAccessCount, PasswordProtected, Uploaded, OwnerPrivateKeyProtected, PrivateNoteCiphertext
                FROM collects WHERE OwnerUserId = @owner ORDER BY CreatedAt DESC LIMIT 100
                """;
            cmd.Parameters.AddWithValue("@owner", ownerId);
            using var reader = cmd.ExecuteReader();
            while (reader.Read())
            {
                var uploaded = reader.GetInt32(9) == 1;
                var item = ReadHome(reader, "collect", uploaded, now) with
                {
                    HasOwnerKey = !reader.IsDBNull(10),
                    PrivateNoteCiphertext = reader.IsDBNull(11) ? null : reader.GetString(11),
                };
                if (item.Status is not ("expired" or "consumed")) items.Add(item);
            }
        }

        return items.OrderByDescending(i => i.CreatedAt).Take(100).ToList();
    }

    public bool DeleteSend(string ownerId, string id)
    {
        using var conn = database.Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "DELETE FROM secrets WHERE Id = @id AND OwnerUserId = @owner";
        cmd.Parameters.AddWithValue("@id", id);
        cmd.Parameters.AddWithValue("@owner", ownerId);
        return cmd.ExecuteNonQuery() == 1;
    }

    public bool DeleteCollect(string ownerId, string id)
    {
        using var conn = database.Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "DELETE FROM collects WHERE Id = @id AND OwnerUserId = @owner";
        cmd.Parameters.AddWithValue("@id", id);
        cmd.Parameters.AddWithValue("@owner", ownerId);
        return cmd.ExecuteNonQuery() == 1;
    }

    public SendPublic? SendMeta(string id) => ReadSend(id, includePayload: false);

    public SendPublic? TakeSend(string id)
    {
        var row = ReadSend(id, includePayload: true);
        if (row is null || row.Status != "active")
        {
            return row;
        }

        using var conn = database.Open();
        using var cmd = conn.CreateCommand();
        if (row.OneTime)
        {
            cmd.CommandText = "UPDATE secrets SET ConsumedAt = @now, AccessCount = AccessCount + 1, Ciphertext = '', Iv = '', WrappedKey = '', EphemeralPublicKey = '' WHERE Id = @id AND ConsumedAt IS NULL AND ExpiresAt >= @now";
        }
        else
        {
            cmd.CommandText = "UPDATE secrets SET AccessCount = AccessCount + 1, ConsumedAt = CASE WHEN MaxAccessCount IS NOT NULL AND AccessCount + 1 >= MaxAccessCount THEN @now ELSE ConsumedAt END, Ciphertext = CASE WHEN MaxAccessCount IS NOT NULL AND AccessCount + 1 >= MaxAccessCount THEN '' ELSE Ciphertext END, Iv = CASE WHEN MaxAccessCount IS NOT NULL AND AccessCount + 1 >= MaxAccessCount THEN '' ELSE Iv END, WrappedKey = CASE WHEN MaxAccessCount IS NOT NULL AND AccessCount + 1 >= MaxAccessCount THEN '' ELSE WrappedKey END, EphemeralPublicKey = CASE WHEN MaxAccessCount IS NOT NULL AND AccessCount + 1 >= MaxAccessCount THEN '' ELSE EphemeralPublicKey END WHERE Id = @id AND ConsumedAt IS NULL AND ExpiresAt >= @now AND (MaxAccessCount IS NULL OR AccessCount < MaxAccessCount)";
        }

        cmd.Parameters.AddWithValue("@now", DateTimeOffset.UtcNow.ToString("O"));
        cmd.Parameters.AddWithValue("@id", id);
        return cmd.ExecuteNonQuery() == 1 ? row : null;
    }

    public CollectPublic? CollectMeta(string id)
    {
        using var conn = database.Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = """
            SELECT PublicKey, ExpiresAt, Uploaded, OneTime, PasswordProtected, ConsumedAt, Filename, ContentType, PublicLabel, AccessCount, MaxAccessCount, HideTextByDefault
            FROM collects WHERE Id = @id
            """;
        cmd.Parameters.AddWithValue("@id", id);
        using var reader = cmd.ExecuteReader();
        if (!reader.Read())
        {
            return null;
        }

        var expires = DateTimeOffset.Parse(reader.GetString(1), System.Globalization.CultureInfo.InvariantCulture);
        var uploaded = reader.GetInt32(2) == 1;
        var consumed = !reader.IsDBNull(5);
        var access = reader.GetInt32(9);
        var max = reader.IsDBNull(10) ? (int?)null : reader.GetInt32(10);
        var exhausted = max is int cap && access >= cap;
        var status = expires < DateTimeOffset.UtcNow ? "expired" : uploaded ? (consumed || exhausted ? "consumed" : "ready") : "waiting";
        return new CollectPublic(reader.GetString(0), expires, status, reader.GetInt32(3) == 1, reader.GetInt32(4) == 1, reader.IsDBNull(6) ? null : reader.GetString(6), reader.IsDBNull(7) ? null : reader.GetString(7), reader.IsDBNull(8) ? null : reader.GetString(8), access, max, reader.GetInt32(11) == 1);
    }

    public string? SaveUpload(string id, UploadInput input)
    {
        var meta = CollectMeta(id);
        if (meta is null)
        {
            return "Collect not found.";
        }

        if (meta.Status != "waiting")
        {
            return "This collect is not open for upload.";
        }

        using var conn = database.Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = """
            UPDATE collects
            SET Uploaded = 1, Ciphertext = @ct, Iv = @iv, WrappedKey = @wk, EphemeralPublicKey = @eph, ContentType = @type, Filename = @file
            WHERE Id = @id AND Uploaded = 0
            """;
        cmd.Parameters.AddWithValue("@ct", input.Ciphertext);
        cmd.Parameters.AddWithValue("@iv", input.Iv);
        cmd.Parameters.AddWithValue("@wk", input.WrappedKey);
        cmd.Parameters.AddWithValue("@eph", input.EphemeralPublicKey);
        cmd.Parameters.AddWithValue("@type", input.ContentType);
        cmd.Parameters.AddWithValue("@file", (object?)input.Filename ?? DBNull.Value);
        cmd.Parameters.AddWithValue("@id", id);
        return cmd.ExecuteNonQuery() == 1 ? null : "This collect is not open for upload.";
    }

    /// <summary>Anyone with the link. Proof of work is enforced by the caller before this burns the upload.</summary>
    public SendPublic? TakeCollect(string id)
    {
        using var conn = database.Open();
        using var sel = conn.CreateCommand();
        sel.CommandText = """
            SELECT OwnerUserId, Ciphertext, Iv, WrappedKey, EphemeralPublicKey, ContentType, Filename, OneTime, ExpiresAt, ConsumedAt, PasswordProtected, HideTextByDefault, Uploaded, AccessCount, MaxAccessCount
            FROM collects WHERE Id = @id
            """;
        sel.Parameters.AddWithValue("@id", id);
        using var reader = sel.ExecuteReader();
        if (!reader.Read() || reader.GetInt32(12) != 1 || reader.IsDBNull(1))
        {
            return null;
        }

        var expires = DateTimeOffset.Parse(reader.GetString(8), System.Globalization.CultureInfo.InvariantCulture);
        var consumed = !reader.IsDBNull(9);
        if (expires < DateTimeOffset.UtcNow || consumed)
        {
            return null;
        }

        var oneTime = reader.GetInt32(7) == 1;
        var access = reader.GetInt32(13);
        var max = reader.IsDBNull(14) ? (int?)null : reader.GetInt32(14);
        if (!oneTime && max is int already && access >= already)
        {
            return null;
        }

        var row = new SendPublic(reader.GetString(1), reader.GetString(2), reader.GetString(3), reader.GetString(4), reader.GetString(5), reader.IsDBNull(6) ? null : reader.GetString(6), oneTime, reader.GetInt32(10) == 1, reader.GetInt32(11) == 1, "ready", expires);
        reader.Close();
        var burn = oneTime || (max is int cap && access + 1 >= cap);
        using var upd = conn.CreateCommand();
        if (burn)
        {
            upd.CommandText = "UPDATE collects SET AccessCount = AccessCount + 1, ConsumedAt = @now, Ciphertext = NULL, Iv = NULL, WrappedKey = NULL, EphemeralPublicKey = NULL WHERE Id = @id AND ConsumedAt IS NULL AND Uploaded = 1 AND ExpiresAt >= @now AND (MaxAccessCount IS NULL OR AccessCount < MaxAccessCount)";
        }
        else
        {
            upd.CommandText = "UPDATE collects SET AccessCount = AccessCount + 1 WHERE Id = @id AND ConsumedAt IS NULL AND Uploaded = 1 AND ExpiresAt >= @now AND (MaxAccessCount IS NULL OR AccessCount < MaxAccessCount)";
        }

        upd.Parameters.AddWithValue("@now", DateTimeOffset.UtcNow.ToString("O"));
        upd.Parameters.AddWithValue("@id", id);
        return upd.ExecuteNonQuery() == 1 ? row : null;
    }

    public string? OwnerKey(string ownerId, string id)
    {
        using var conn = database.Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT OwnerPrivateKeyProtected FROM collects WHERE Id = @id AND OwnerUserId = @owner";
        cmd.Parameters.AddWithValue("@id", id);
        cmd.Parameters.AddWithValue("@owner", ownerId);
        return cmd.ExecuteScalar() as string;
    }

    private SendPublic? ReadSend(string id, bool includePayload)
    {
        using var conn = database.Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = """
            SELECT Ciphertext, Iv, WrappedKey, EphemeralPublicKey, ContentType, Filename, OneTime, ExpiresAt, ConsumedAt, PasswordProtected, HideTextByDefault, AccessCount, MaxAccessCount, RecipientLabel
            FROM secrets WHERE Id = @id
            """;
        cmd.Parameters.AddWithValue("@id", id);
        using var reader = cmd.ExecuteReader();
        if (!reader.Read())
        {
            return null;
        }

        var expires = DateTimeOffset.Parse(reader.GetString(7), System.Globalization.CultureInfo.InvariantCulture);
        var consumed = !reader.IsDBNull(8);
        var access = reader.GetInt32(11);
        var max = reader.IsDBNull(12) ? (int?)null : reader.GetInt32(12);
        var status = expires < DateTimeOffset.UtcNow ? "expired" : consumed || (max is int cap && access >= cap) ? "consumed" : "active";
        return new SendPublic(
            includePayload && status == "active" ? reader.GetString(0) : "",
            includePayload && status == "active" ? reader.GetString(1) : "",
            includePayload && status == "active" ? reader.GetString(2) : "",
            includePayload && status == "active" ? reader.GetString(3) : "",
            reader.GetString(4),
            reader.IsDBNull(5) ? null : reader.GetString(5),
            reader.GetInt32(6) == 1,
            reader.GetInt32(9) == 1,
            reader.GetInt32(10) == 1,
            status,
            expires,
            access,
            max,
            reader.IsDBNull(13) ? null : reader.GetString(13));
    }

    private static HomeItem ReadHome(SqliteDataReader reader, string kind, bool uploaded, DateTimeOffset now)
    {
        var expires = DateTimeOffset.Parse(reader.GetString(4), System.Globalization.CultureInfo.InvariantCulture);
        var consumed = !reader.IsDBNull(5);
        var access = reader.GetInt32(6);
        var max = reader.IsDBNull(7) ? (int?)null : reader.GetInt32(7);
        var exhausted = max is int cap && access >= cap;
        var status = expires < now
            ? "expired"
            : kind == "collect" && !uploaded
                ? "waiting"
                : consumed || exhausted ? "consumed" : kind == "collect" ? "ready" : "active";
        return new HomeItem(reader.GetString(0), kind, reader.IsDBNull(1) ? null : reader.GetString(1), status, reader.GetInt32(2) == 1, DateTimeOffset.Parse(reader.GetString(3), System.Globalization.CultureInfo.InvariantCulture), expires, reader.GetInt32(6), reader.IsDBNull(7) ? null : reader.GetInt32(7), reader.GetInt32(8) == 1, false);
    }

    private static void BindCommon(SqliteCommand cmd, string id, string ownerId, SendInput input, DateTimeOffset now)
    {
        cmd.Parameters.AddWithValue("@id", id);
        cmd.Parameters.AddWithValue("@owner", ownerId);
        cmd.Parameters.AddWithValue("@label", (object?)input.EncryptedLabel ?? DBNull.Value);
        cmd.Parameters.AddWithValue("@ct", input.Ciphertext);
        cmd.Parameters.AddWithValue("@iv", input.Iv);
        cmd.Parameters.AddWithValue("@wk", input.WrappedKey);
        cmd.Parameters.AddWithValue("@eph", input.EphemeralPublicKey);
        cmd.Parameters.AddWithValue("@type", input.ContentType);
        cmd.Parameters.AddWithValue("@file", (object?)input.Filename ?? DBNull.Value);
        cmd.Parameters.AddWithValue("@once", input.OneTime ? 1 : 0);
        cmd.Parameters.AddWithValue("@created", now.ToString("O"));
        cmd.Parameters.AddWithValue("@expires", now.AddMinutes(input.ExpiresInHours).ToString("O"));
        cmd.Parameters.AddWithValue("@note", (object?)input.PrivateNoteCiphertext ?? DBNull.Value);
        cmd.Parameters.AddWithValue("@max", (object?)input.MaxAccessCount ?? DBNull.Value);
        cmd.Parameters.AddWithValue("@pw", input.PasswordProtected ? 1 : 0);
        cmd.Parameters.AddWithValue("@hide", input.HideTextByDefault ? 1 : 0);
        cmd.Parameters.AddWithValue("@cidr", (object?)input.AllowedCidr ?? DBNull.Value);
        cmd.Parameters.AddWithValue("@recipient", (object?)input.RecipientLabel ?? DBNull.Value);
    }

    public string? AllowedCidr(string id)
    {
        using var conn = database.Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT AllowedCidr FROM secrets WHERE Id = @id";
        cmd.Parameters.AddWithValue("@id", id);
        var value = cmd.ExecuteScalar();
        return value is string s && s.Length > 0 ? s : null;
    }

    private static string NewId() => Base64Url.Encode(RandomNumberGenerator.GetBytes(16));
}

public sealed record UserDataKeyWrap(string Kind, string CredentialId, string Wrapped);

public sealed record NotificationPrefs(string Email, bool NotifyCollectReady, bool NotifySendOpened);

public sealed record NotifyTarget(string UserId, string Email);

public sealed record SendInput(string Ciphertext, string Iv, string WrappedKey, string EphemeralPublicKey, string ContentType, string? Filename, bool OneTime, int ExpiresInHours, string? EncryptedLabel, string? PrivateNoteCiphertext, int? MaxAccessCount, bool PasswordProtected, bool HideTextByDefault, string? AllowedCidr = null, string? RecipientLabel = null);

public sealed record CollectInput(string PublicKey, string? OwnerPrivateKeyProtected, string? EncryptedLabel, string? PrivateNoteCiphertext, bool OneTime, int ExpiresInMinutes, int? MaxAccessCount, bool PasswordProtected, bool HideTextByDefault, string? PublicLabel);

public sealed record UploadInput(string Ciphertext, string Iv, string WrappedKey, string EphemeralPublicKey, string ContentType, string? Filename);

public sealed record HomeItem(string Id, string Kind, string? EncryptedLabel, string Status, bool OneTime, DateTimeOffset CreatedAt, DateTimeOffset ExpiresAt, int AccessCount, int? MaxAccessCount, bool PasswordProtected, bool HasOwnerKey, string? PrivateNoteCiphertext = null, bool IpRestricted = false);

public sealed record SendPublic(string Ciphertext, string Iv, string WrappedKey, string EphemeralPublicKey, string ContentType, string? Filename, bool OneTime, bool PasswordProtected, bool HideTextByDefault, string Status, DateTimeOffset ExpiresAt, int AccessCount = 0, int? MaxAccessCount = null, string? RecipientLabel = null);

public sealed record CollectPublic(string PublicKey, DateTimeOffset ExpiresAt, string Status, bool OneTime, bool PasswordProtected, string? Filename, string? ContentType, string? PublicLabel, int AccessCount = 0, int? MaxAccessCount = null, bool HideTextByDefault = false);
