// Services/SteamOpenIdLoopbackService.cs
// Implements OpenID 2.0 verification against Steam with CSRF protection.
using System;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Web;

namespace RustPlusDesk.Services;

public class SteamOpenIdLoopbackService
{
    private const string SteamOpenId = "https://steamcommunity.com/openid/login";

    public async Task<string> SignInAsync(int port = 0)
    {
        // Use random port if not specified (reduces predictability)
        if (port == 0)
            port = RandomNumberGenerator.GetInt32(52000, 65000);

        // CSRF protection: random state nonce
        var stateBytes = new byte[16];
        RandomNumberGenerator.Fill(stateBytes);
        var state = Convert.ToHexString(stateBytes).ToLowerInvariant();

        // STATE MUST be inside return_to — Steam echoes openid.* params only.
        var returnTo = $"http://127.0.0.1:{port}/steam/openid/return?state={Uri.EscapeDataString(state)}";
        var realm = $"http://127.0.0.1:{port}/";

        var q = HttpUtility.ParseQueryString(string.Empty);
        q["openid.ns"] = "http://specs.openid.net/auth/2.0";
        q["openid.mode"] = "checkid_setup";
        q["openid.return_to"] = returnTo;
        q["openid.realm"] = realm;
        q["openid.claimed_id"] = "http://specs.openid.net/auth/2.0/identifier_select";
        q["openid.identity"] = "http://specs.openid.net/auth/2.0/identifier_select";
        var openIdUrl = $"{SteamOpenId}?{q}";

        using var listener = new HttpListener();
        listener.Prefixes.Add(realm);
        listener.Start();

        Process.Start(new ProcessStartInfo(openIdUrl) { UseShellExecute = true });

        var ctx = await listener.GetContextAsync();
        var req = ctx.Request;

        try
        {
            // 1) Verify state matches (CSRF protection)
            var returnedState = req.QueryString.Get("state");
            if (!string.Equals(returnedState, state, StringComparison.Ordinal))
            {
                throw new InvalidOperationException("OpenID state mismatch — possible CSRF attack.");
            }

            // 2) Verify OpenID signature with Steam
            await VerifyWithSteamAsync(req);

            // 3) Extract SteamID64
            var claimed = req.QueryString.Get("openid.claimed_id");
            var sid = "";
            if (!string.IsNullOrEmpty(claimed))
            {
                var i = claimed.LastIndexOf('/');
                if (i >= 0 && i < claimed.Length - 1)
                    sid = claimed[(i + 1)..];
            }

            if (string.IsNullOrEmpty(sid))
                throw new InvalidOperationException("SteamID64 konnte nicht gelesen werden.");

            // Success page
            var html = @"<html><body style='font-family:sans-serif'>
                          <h2>Connected to Steam. </h2>
                          <p>Your ID is paired to Rust Plus App, ma dawg. You can now safely close this browser window. This process was only required once. </p>
                         </body></html>";
            var buf = Encoding.UTF8.GetBytes(html);
            ctx.Response.ContentType = "text/html; charset=utf-8";
            ctx.Response.ContentLength64 = buf.Length;
            await ctx.Response.OutputStream.WriteAsync(buf, 0, buf.Length);

            return sid;
        }
        finally
        {
            ctx.Response.Close();
            listener.Stop();
        }
    }

    private static async Task VerifyWithSteamAsync(HttpListenerRequest req)
    {
        // Collect all openid.* parameters and post them back to Steam
        var form = new System.Collections.Specialized.NameValueCollection();
        foreach (var key in req.QueryString.AllKeys)
        {
            if (key == null) continue;
            if (key.StartsWith("openid.", StringComparison.OrdinalIgnoreCase))
                form[key] = req.QueryString[key];
        }

        // Override mode to check_authentication
        form["openid.mode"] = "check_authentication";

        using var http = new HttpClient();
        var content = new FormUrlEncodedContent(
            form.AllKeys.Select(k => new System.Collections.Generic.KeyValuePair<string, string>(k!, form[k]!)));

        var resp = await http.PostAsync(SteamOpenId, content);
        var body = await resp.Content.ReadAsStringAsync();

        if (!body.Contains("is_valid:true"))
        {
            throw new InvalidOperationException("Steam OpenID verification failed. Response did not contain is_valid:true.");
        }
    }
}
