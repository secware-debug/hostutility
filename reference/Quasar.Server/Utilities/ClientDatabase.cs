using Microsoft.Data.Sqlite;
using System;
using System.Collections.Generic;
using System.IO;
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
    Country TEXT,
    CountryCode TEXT,
    OperatingSystem TEXT,
    AccountType TEXT,
    ImageIndex INTEGER,
    InstallTimeUtc TEXT NOT NULL,
    LastPingTimeUtc TEXT NULL
);";
                        cmd.ExecuteNonQuery();
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

                StageNativeDll(
                    Path.Combine(baseDir, "win-x64", "e_sqlite3.dll"),
                    Path.Combine(baseDir, "runtimes", "win-x64", "native", "e_sqlite3.dll"));

                StageNativeDll(
                    Path.Combine(baseDir, "win-x86", "e_sqlite3.dll"),
                    Path.Combine(baseDir, "runtimes", "win-x86", "native", "e_sqlite3.dll"));
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
    Uuid, IpAddress, Tag, UserPc, Version, Status, UserStatus,
    Country, CountryCode, OperatingSystem, AccountType,
    ImageIndex, InstallTimeUtc, LastPingTimeUtc
FROM Clients
ORDER BY InstallTimeUtc ASC;";

                        using (var reader = cmd.ExecuteReader())
                        {
                            var result = new List<ClientRow>();
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
                                    Country = reader.IsDBNull(7) ? "" : reader.GetString(7),
                                    CountryCode = reader.IsDBNull(8) ? "" : reader.GetString(8),
                                    OperatingSystem = reader.IsDBNull(9) ? "" : reader.GetString(9),
                                    AccountType = reader.IsDBNull(10) ? "" : reader.GetString(10),
                                    ImageIndex = reader.IsDBNull(11) ? 0 : reader.GetInt32(11),
                                    InstallTimeUtc = ParseNullableUtc(reader.IsDBNull(12) ? null : reader.GetString(12)),
                                    LastPingTimeUtc = ParseNullableUtc(reader.IsDBNull(13) ? null : reader.GetString(13))
                                };

                                result.Add(row);
                            }

                            return result;
                        }
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
    Country = excluded.Country,
    CountryCode = excluded.CountryCode,
    OperatingSystem = excluded.OperatingSystem,
    AccountType = excluded.AccountType,
    ImageIndex = excluded.ImageIndex,
    LastPingTimeUtc = NULL;"; // keep InstallTimeUtc, force LastPingTimeUtc to remain NULL
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
                            Country = country ?? "",
                            CountryCode = countryCode ?? "",
                            OperatingSystem = operatingSystem ?? "",
                            AccountType = accountType ?? "",
                            ImageIndex = imageIndex,
                            InstallTimeUtc = existingInstallUtc,
                            LastPingTimeUtc = null
                        };
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
    }

    public sealed class ClientRow
    {
        public string Uuid { get; set; } = "";
        public string IpAddress { get; set; } = "";
        public string Tag { get; set; } = "";
        public string UserPc { get; set; } = "";
        public string Version { get; set; } = "";
        public string Status { get; set; } = "Disconnected";
        public string UserStatus { get; set; } = "";
        public string Country { get; set; } = "";
        public string CountryCode { get; set; } = "";
        public string OperatingSystem { get; set; } = "";
        public string AccountType { get; set; } = "";
        public int ImageIndex { get; set; }
        public DateTime? InstallTimeUtc { get; set; }
        public DateTime? LastPingTimeUtc { get; set; }
    }
}

