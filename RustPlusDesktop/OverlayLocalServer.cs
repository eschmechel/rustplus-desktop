// Services/OverlayLocalServer.cs
// Local-only HTTP server for overlay sync. Binds 127.0.0.1 on a random port.
// No external auth required (localhost-only). Path traversal is strictly validated.
using System;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace RustPlusDesk.Services;

public sealed class OverlayLocalServer : IDisposable
{
    private HttpListener? _listener;
    private Task? _listenTask;
    private CancellationTokenSource? _cts;

    public string BaseUrl { get; private set; } = "";

    private static string OverlayBaseDir => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
        "RustPlusDesk", "Overlays");

    public bool Start()
    {
        Stop();

        _cts = new CancellationTokenSource();
        _listener = new HttpListener();

        // Try a few random ports on 127.0.0.1
        for (int attempt = 0; attempt < 10; attempt++)
        {
            int port = Random.Shared.Next(52000, 65000);
            string prefix = $"http://127.0.0.1:{port}/";
            try
            {
                _listener.Prefixes.Clear();
                _listener.Prefixes.Add(prefix);
                _listener.Start();
                BaseUrl = prefix.TrimEnd('/');
                _listenTask = Task.Run(() => ListenLoop(_cts.Token));
                return true;
            }
            catch
            {
                // port in use, try next
            }
        }

        _listener = null;
        return false;
    }

    public void Stop()
    {
        _cts?.Cancel();
        try { _listener?.Stop(); } catch { }
        try { _listenTask?.Wait(TimeSpan.FromSeconds(2)); } catch { }
        _listener?.Close();
        _listener = null;
        _listenTask = null;
        _cts = null;
        BaseUrl = "";
    }

    public void Dispose() => Stop();

    private async Task ListenLoop(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested && _listener != null)
        {
            try
            {
                var ctx = await _listener.GetContextAsync();
                _ = Task.Run(() => HandleRequest(ctx), ct);
            }
            catch (ObjectDisposedException) { break; }
            catch (HttpListenerException) { break; }
            catch (OperationCanceledException) { break; }
            catch { /* ignore transient errors */ }
        }
    }

    private void HandleRequest(HttpListenerContext ctx)
    {
        try
        {
            var req = ctx.Request;
            var resp = ctx.Response;

            // Add CORS header for local debugging (harmless on 127.0.0.1)
            resp.Headers.Add("Access-Control-Allow-Origin", "*");

            if (req.HttpMethod == "POST" && req.Url?.AbsolutePath == "/upload")
            {
                HandleUpload(req, resp);
            }
            else if (req.HttpMethod == "GET" && req.Url?.AbsolutePath == "/fetch")
            {
                HandleFetch(req, resp);
            }
            else
            {
                SendJson(resp, 404, new { error = "not_found" });
            }
        }
        catch (Exception ex)
        {
            try
            {
                ctx.Response.StatusCode = 500;
                ctx.Response.Close();
            }
            catch { }
        }
    }

    private void HandleUpload(HttpListenerRequest req, HttpListenerResponse resp)
    {
        string body;
        using (var sr = new StreamReader(req.InputStream, req.ContentEncoding))
            body = sr.ReadToEnd();

        string? steamId = null;
        string? serverKey = null;
        string? overlayB64 = null;

        try
        {
            using var doc = JsonDocument.Parse(body);
            var root = doc.RootElement;
            if (root.TryGetProperty("steamId", out var s)) steamId = s.GetString();
            if (root.TryGetProperty("serverKey", out var k)) serverKey = k.GetString();
            if (root.TryGetProperty("overlayJsonB64", out var b)) overlayB64 = b.GetString();
        }
        catch
        {
            SendJson(resp, 400, new { error = "bad_json" });
            return;
        }

        if (string.IsNullOrWhiteSpace(steamId) ||
            string.IsNullOrWhiteSpace(serverKey) ||
            string.IsNullOrWhiteSpace(overlayB64))
        {
            SendJson(resp, 400, new { error = "missing_field" });
            return;
        }

        // Path traversal protection
        if (!IsValidServerKey(serverKey))
        {
            SendJson(resp, 400, new { error = "invalid_server_key" });
            return;
        }

        byte[] overlayBytes;
        try
        {
            overlayBytes = Convert.FromBase64String(overlayB64);
        }
        catch
        {
            SendJson(resp, 400, new { error = "bad_b64" });
            return;
        }

        const int maxBytes = 350_000;
        if (overlayBytes.Length > maxBytes)
        {
            SendJson(resp, 413, new { error = "too_large" });
            return;
        }

        // Sanitize steamId to digits only
        var safeSteamId = new string(steamId.Where(char.IsDigit).ToArray());
        if (string.IsNullOrEmpty(safeSteamId))
        {
            SendJson(resp, 400, new { error = "invalid_steamid" });
            return;
        }

        var dir = Path.Combine(OverlayBaseDir, serverKey);
        Directory.CreateDirectory(dir);
        var tmp = Path.Combine(dir, $"{safeSteamId}.json.tmp");
        var final = Path.Combine(dir, $"{safeSteamId}.json");

        try
        {
            File.WriteAllBytes(tmp, overlayBytes);
            File.Move(tmp, final, overwrite: true);
            SendJson(resp, 200, new { status = "ok" });
        }
        catch (Exception ex)
        {
            SendJson(resp, 500, new { error = "io_error", detail = ex.Message });
        }
    }

    private void HandleFetch(HttpListenerRequest req, HttpListenerResponse resp)
    {
        var q = req.QueryString;
        var steamId = q["steamId"];
        var serverKey = q["serverKey"];

        if (string.IsNullOrWhiteSpace(steamId) || string.IsNullOrWhiteSpace(serverKey))
        {
            SendJson(resp, 400, new { error = "missing_field" });
            return;
        }

        if (!IsValidServerKey(serverKey))
        {
            SendJson(resp, 400, new { error = "invalid_server_key" });
            return;
        }

        var safeSteamId = new string(steamId.Where(char.IsDigit).ToArray());
        if (string.IsNullOrEmpty(safeSteamId))
        {
            SendJson(resp, 400, new { error = "invalid_steamid" });
            return;
        }

        var filePath = Path.Combine(OverlayBaseDir, serverKey, $"{safeSteamId}.json");

        if (!File.Exists(filePath))
        {
            SendJson(resp, 404, new { error = "not_found" });
            return;
        }

        try
        {
            var bytes = File.ReadAllBytes(filePath);
            var b64 = Convert.ToBase64String(bytes);
            SendJson(resp, 200, new { overlayJsonB64 = b64 });
        }
        catch (Exception ex)
        {
            SendJson(resp, 500, new { error = "io_error", detail = ex.Message });
        }
    }

    private static bool IsValidServerKey(string serverKey)
    {
        // Strict: alphanumerics, hyphens, underscores only. No dots (prevents traversal).
        if (string.IsNullOrEmpty(serverKey) || serverKey.Length > 128)
            return false;

        foreach (var ch in serverKey)
        {
            if (!char.IsLetterOrDigit(ch) && ch != '-' && ch != '_')
                return false;
        }
        return true;
    }

    private static void SendJson(HttpListenerResponse resp, int code, object obj)
    {
        var json = JsonSerializer.Serialize(obj);
        var bytes = Encoding.UTF8.GetBytes(json);
        resp.StatusCode = code;
        resp.ContentType = "application/json; charset=utf-8";
        resp.ContentLength64 = bytes.Length;
        resp.OutputStream.Write(bytes, 0, bytes.Length);
        resp.Close();
    }
}
