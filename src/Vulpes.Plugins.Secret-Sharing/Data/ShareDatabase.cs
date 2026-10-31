using Microsoft.Data.Sqlite;

namespace Vulpes.Plugins.SecretSharing.Data;

/// <summary>Plugin SQLite database. The server stores ciphertext only.</summary>
public sealed class ShareDatabase
{
    private readonly string _path;

    public ShareDatabase(string path)
    {
        _path = path;
        var directory = Path.GetDirectoryName(path);
        if (!string.IsNullOrEmpty(directory))
        {
            Directory.CreateDirectory(directory);
        }

        using var conn = Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = """
            CREATE TABLE IF NOT EXISTS user_data_keys (
                UserId TEXT PRIMARY KEY NOT NULL,
                Wrapped TEXT NOT NULL,
                CreatedAt TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS user_data_key_wraps (
                UserId TEXT NOT NULL,
                Kind TEXT NOT NULL,
                CredentialId TEXT NOT NULL,
                Wrapped TEXT NOT NULL,
                CreatedAt TEXT NOT NULL,
                PRIMARY KEY (UserId, Kind, CredentialId)
            );

            CREATE TABLE IF NOT EXISTS notification_prefs (
                UserId TEXT PRIMARY KEY NOT NULL,
                Email TEXT NOT NULL DEFAULT '',
                NotifyCollectReady INTEGER NOT NULL DEFAULT 0,
                NotifySendOpened INTEGER NOT NULL DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS notify_email_budget (
                Email TEXT PRIMARY KEY NOT NULL,
                SendCount INTEGER NOT NULL,
                LastSendMs INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS pow_challenges (
                Id TEXT PRIMARY KEY NOT NULL,
                ResourceKind TEXT NOT NULL,
                ResourceId TEXT NOT NULL,
                HmacKey BLOB NOT NULL,
                DifficultyBits INTEGER NOT NULL,
                ExpiresAt TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS scan_events (
                Id INTEGER PRIMARY KEY AUTOINCREMENT,
                Kind TEXT NOT NULL,
                ClientKey TEXT NOT NULL,
                AtMs INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS secrets (
                Id TEXT PRIMARY KEY NOT NULL,
                OwnerUserId TEXT NOT NULL,
                EncryptedLabel TEXT NULL,
                Ciphertext TEXT NOT NULL,
                Iv TEXT NOT NULL,
                WrappedKey TEXT NOT NULL,
                EphemeralPublicKey TEXT NOT NULL,
                ContentType TEXT NOT NULL,
                Filename TEXT NULL,
                OneTime INTEGER NOT NULL,
                CreatedAt TEXT NOT NULL,
                ExpiresAt TEXT NOT NULL,
                ConsumedAt TEXT NULL,
                PrivateNoteCiphertext TEXT NULL,
                MaxAccessCount INTEGER NULL,
                AccessCount INTEGER NOT NULL DEFAULT 0,
                PasswordProtected INTEGER NOT NULL DEFAULT 0,
                HideTextByDefault INTEGER NOT NULL DEFAULT 0,
                AllowedCidr TEXT NULL,
                RecipientLabel TEXT NULL
            );
            CREATE INDEX IF NOT EXISTS ix_secrets_owner ON secrets(OwnerUserId);

            CREATE TABLE IF NOT EXISTS collects (
                Id TEXT PRIMARY KEY NOT NULL,
                OwnerUserId TEXT NOT NULL,
                EncryptedLabel TEXT NULL,
                PublicKey TEXT NOT NULL,
                OwnerPrivateKeyProtected TEXT NULL,
                OneTime INTEGER NOT NULL,
                CreatedAt TEXT NOT NULL,
                ExpiresAt TEXT NOT NULL,
                Uploaded INTEGER NOT NULL DEFAULT 0,
                Ciphertext TEXT NULL,
                Iv TEXT NULL,
                WrappedKey TEXT NULL,
                EphemeralPublicKey TEXT NULL,
                ContentType TEXT NULL,
                Filename TEXT NULL,
                ConsumedAt TEXT NULL,
                PrivateNoteCiphertext TEXT NULL,
                MaxAccessCount INTEGER NULL,
                AccessCount INTEGER NOT NULL DEFAULT 0,
                PasswordProtected INTEGER NOT NULL DEFAULT 0,
                HideTextByDefault INTEGER NOT NULL DEFAULT 0,
                PublicLabel TEXT NULL
            );
            CREATE INDEX IF NOT EXISTS ix_collects_owner ON collects(OwnerUserId);
            """;
        cmd.ExecuteNonQuery();
        EnsurePowClientId(conn);
        EnsurePublicLabel(conn);
        EnsureAllowedCidr(conn);
        EnsureRecipientLabel(conn);
    }

    private static void EnsurePowClientId(SqliteConnection conn)
    {
        using var check = conn.CreateCommand();
        check.CommandText = "SELECT 1 FROM pragma_table_info('pow_challenges') WHERE name = 'ClientId' LIMIT 1";
        if (check.ExecuteScalar() is not null)
        {
            return;
        }

        using var alter = conn.CreateCommand();
        alter.CommandText = "ALTER TABLE pow_challenges ADD COLUMN ClientId TEXT NOT NULL DEFAULT ''";
        alter.ExecuteNonQuery();
    }

    private static void EnsurePublicLabel(SqliteConnection conn)
    {
        using var check = conn.CreateCommand();
        check.CommandText = "SELECT 1 FROM pragma_table_info('collects') WHERE name = 'PublicLabel' LIMIT 1";
        if (check.ExecuteScalar() is not null)
        {
            return;
        }

        using var alter = conn.CreateCommand();
        alter.CommandText = "ALTER TABLE collects ADD COLUMN PublicLabel TEXT NULL";
        alter.ExecuteNonQuery();
    }

    private static void EnsureAllowedCidr(SqliteConnection conn)
    {
        using var check = conn.CreateCommand();
        check.CommandText = "SELECT 1 FROM pragma_table_info('secrets') WHERE name = 'AllowedCidr' LIMIT 1";
        if (check.ExecuteScalar() is not null)
        {
            return;
        }

        using var alter = conn.CreateCommand();
        alter.CommandText = "ALTER TABLE secrets ADD COLUMN AllowedCidr TEXT NULL";
        alter.ExecuteNonQuery();
    }

    private static void EnsureRecipientLabel(SqliteConnection conn)
    {
        using var check = conn.CreateCommand();
        check.CommandText = "SELECT 1 FROM pragma_table_info('secrets') WHERE name = 'RecipientLabel' LIMIT 1";
        if (check.ExecuteScalar() is not null)
        {
            return;
        }

        using var alter = conn.CreateCommand();
        alter.CommandText = "ALTER TABLE secrets ADD COLUMN RecipientLabel TEXT NULL";
        alter.ExecuteNonQuery();
    }

    public SqliteConnection Open()
    {
        var conn = new SqliteConnection($"Data Source={_path}");
        conn.Open();
        using var pragma = conn.CreateCommand();
        pragma.CommandText = "PRAGMA busy_timeout = 5000;";
        pragma.ExecuteNonQuery();
        return conn;
    }
}
