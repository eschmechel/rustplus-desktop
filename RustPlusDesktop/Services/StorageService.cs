using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using RustPlusDesk.Models;

namespace RustPlusDesk.Services;

public static class StorageService
{
    private static string AppDir =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "RustPlusDesk");

    private static string ProfilesPath => Path.Combine(AppDir, "profiles.json");

    // SECURITY: DPAPI-encrypted storage for player tokens.
    // Best-effort: if DPAPI fails for any reason, falls back to plaintext
    // and logs a warning so the user is never locked out of their data.
    public static void SaveProfiles(IEnumerable<ServerProfile> profiles)
    {
        try
        {
            Directory.CreateDirectory(AppDir);
            var json = JsonSerializer.Serialize(profiles, new JsonSerializerOptions { WriteIndented = true });
            var bytes = Encoding.UTF8.GetBytes(json);

            try
            {
                var encrypted = ProtectedData.Protect(bytes, null, DataProtectionScope.CurrentUser);
                // Write atomically: temp -> rename
                var tmp = ProfilesPath + ".tmp";
                File.WriteAllBytes(tmp, encrypted);
                File.Move(tmp, ProfilesPath, overwrite: true);
                // Clean up old plaintext backup if it exists
                var plainBackup = ProfilesPath + ".plain";
                if (File.Exists(plainBackup)) try { File.Delete(plainBackup); } catch { }
            }
            catch (Exception ex)
            {
                // DPAPI failed (e.g., roaming profile, restricted session) — fall back to plaintext
                Console.WriteLine("[StorageService][WARN] DPAPI encryption failed, saving plaintext: " + ex.Message);
                File.WriteAllText(ProfilesPath, json);
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine("[StorageService][ERR] SaveProfiles failed: " + ex);
        }
    }

    public static string GetProfilesPath() =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "RustPlusDesk", "profiles.json");

    public static List<ServerProfile> LoadProfiles()
    {
        if (!File.Exists(ProfilesPath))
        {
            // Check for plaintext backup from a previous failed encryption
            var plainBackup = ProfilesPath + ".plain";
            if (File.Exists(plainBackup))
            {
                try
                {
                    var json = File.ReadAllText(plainBackup);
                    var data = JsonSerializer.Deserialize<List<ServerProfile>>(json);
                    return data ?? new List<ServerProfile>();
                }
                catch { /* ignore */ }
            }
            return new List<ServerProfile>();
        }

        try
        {
            var fileBytes = File.ReadAllBytes(ProfilesPath);

            // Try 1: DPAPI-decrypt + JSON parse
            try
            {
                var decrypted = ProtectedData.Unprotect(fileBytes, null, DataProtectionScope.CurrentUser);
                var json = Encoding.UTF8.GetString(decrypted);
                var result = JsonSerializer.Deserialize<List<ServerProfile>>(json);
                if (result != null) return result;
            }
            catch (CryptographicException)
            {
                // Expected for old plaintext files — fall through to Try 2
            }
            catch (JsonException)
            {
                // Decrypted but not valid JSON — could be corruption, fall through to Try 2
                Console.WriteLine("[StorageService][WARN] Decrypted profiles.json is not valid JSON; trying plaintext fallback.");
            }

            // Try 2: Plaintext JSON parse (migration or DPAPI failure fallback)
            try
            {
                var plaintext = Encoding.UTF8.GetString(fileBytes);
                var data = JsonSerializer.Deserialize<List<ServerProfile>>(plaintext);
                var list = data ?? new List<ServerProfile>();
                if (list.Count > 0)
                {
                    // Re-encrypt in background if we successfully loaded plaintext
                    try { SaveProfiles(list); }
                    catch { /* ignore re-encryption failures */ }
                }
                return list;
            }
            catch (JsonException)
            {
                // Not valid plaintext JSON either — file is truly corrupted
                Console.WriteLine("[StorageService][ERR] profiles.json is neither valid encrypted nor plaintext JSON.");
                // Keep a backup of the corrupted file for debugging
                try
                {
                    var corruptBackup = ProfilesPath + ".corrupt." + DateTime.Now.ToString("yyyyMMddHHmmss");
                    File.Copy(ProfilesPath, corruptBackup, overwrite: true);
                }
                catch { }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine("[StorageService][ERR] LoadProfiles failed: " + ex);
        }

        return new List<ServerProfile>();
    }

    private static string CacheDir => Path.Combine(AppDir, "cache");

    public static void SaveCache<T>(string key, T data)
    {
        try
        {
            Directory.CreateDirectory(CacheDir);
            var path = Path.Combine(CacheDir, key + ".json");
            var json = JsonSerializer.Serialize(data, new JsonSerializerOptions { WriteIndented = true });
            File.WriteAllText(path, json);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"SaveCache Error ({key}): {ex.Message}");
        }
    }

    public static T? LoadCache<T>(string key)
    {
        try
        {
            var path = Path.Combine(CacheDir, key + ".json");
            if (!File.Exists(path)) return default;
            var json = File.ReadAllText(path);
            return JsonSerializer.Deserialize<T>(json);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"LoadCache Error ({key}): {ex.Message}");
            return default;
        }
    }
}
