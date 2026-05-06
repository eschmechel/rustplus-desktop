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
    // Falls back to plaintext load for one-time migration, then re-encrypts.
    public static void SaveProfiles(IEnumerable<ServerProfile> profiles)
    {
        Directory.CreateDirectory(AppDir);
        var json = JsonSerializer.Serialize(profiles, new JsonSerializerOptions { WriteIndented = true });
        var bytes = Encoding.UTF8.GetBytes(json);
        var encrypted = ProtectedData.Protect(bytes, null, DataProtectionScope.CurrentUser);
        File.WriteAllBytes(ProfilesPath, encrypted);
    }

    public static string GetProfilesPath() =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "RustPlusDesk", "profiles.json");

    public static List<ServerProfile> LoadProfiles()
    {
        if (!File.Exists(ProfilesPath)) return new List<ServerProfile>();
        try
        {
            var fileBytes = File.ReadAllBytes(ProfilesPath);
            byte[] decrypted;
            try
            {
                decrypted = ProtectedData.Unprotect(fileBytes, null, DataProtectionScope.CurrentUser);
            }
            catch (CryptographicException)
            {
                // Likely an old plaintext file — try loading as text, then migrate to encrypted.
                var plaintext = Encoding.UTF8.GetString(fileBytes);
                var data = JsonSerializer.Deserialize<List<ServerProfile>>(plaintext);
                var list = data ?? new List<ServerProfile>();
                if (list.Count > 0)
                {
                    SaveProfiles(list); // migrate to encrypted
                }
                return list;
            }
            var json = Encoding.UTF8.GetString(decrypted);
            var result = JsonSerializer.Deserialize<List<ServerProfile>>(json);
            return result ?? new List<ServerProfile>();
        }
        catch (Exception ex)
        {
            Console.WriteLine("LoadProfiles-Fehler: " + ex);
            return new List<ServerProfile>();
        }
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
