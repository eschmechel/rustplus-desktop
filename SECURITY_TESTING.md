# Security E2E Test Plan

This document describes the end-to-end testing strategy for validating the security hardening changes.

## Prerequisites

- Windows 10/11 development machine
- .NET 8 SDK
- Node.js (for running Python backends locally if desired)
- Git

## Build

```powershell
cd RustPlusDesktop
dotnet restore
dotnet build
```

---

## PR 1: Local Overlay Server + Grace Period

### Test 1.1: Local server starts automatically
1. Launch the app (F5 in VS or `dotnet run`)
2. Check the log output for: `[overlay] Local server started at http://127.0.0.1:xxxxx`
3. **Expected**: Server starts on a random port between 52000-65000

### Test 1.2: Overlay upload goes to localhost
1. Connect to a Rust server
2. Create or modify an overlay (draw something, place markers)
3. Check logs for `[overlay] Overlay uploaded`
4. **Expected**: URL in logs should be `http://127.0.0.1:xxxxx/upload`, NOT `http://85.214.193.250:5000`

### Test 1.3: Overlay fetch goes to localhost
1. Have a teammate (or yourself on another SteamID) with an overlay
2. Click their overlay button to fetch
3. Check logs for `[overlay/net]`
4. **Expected**: Fetch URL should be `http://127.0.0.1:xxxxx/fetch?...`, no `sig` parameter

### Test 1.4: Path traversal blocked
1. Manually create a test request to the local server:
   ```powershell
   $r = Invoke-WebRequest -Uri "http://127.0.0.1:YOUR_PORT/fetch?steamId=123&serverKey=../.." -Method GET
   ```
2. **Expected**: HTTP 400 with `{"error":"invalid_server_key"}`

### Test 1.5: Grace period fallback
1. Temporarily break the local server start (e.g., hardcode a conflicted port in OverlayLocalServer.Start)
2. Launch the app before 2026-06-04
3. **Expected**: Log shows `[overlay][DEPRECATED] Local server unavailable; falling back to remote. Update required before 2026-06-04.`
4. Overlay sync should still work via the old remote URL with HMAC

### Test 1.6: Grace period expired
1. Change system clock to after 2026-06-04 (or temporarily edit `s_overlayGracePeriodEnd` in MainWindow.xaml.cs for testing)
2. Ensure local server fails to start
3. **Expected**: Log shows `[overlay][ERROR] Local server unavailable and grace period expired. Overlay sync disabled.`
4. Overlay operations should silently fail (return false)

---

## PR 2: Auto-Updater Integrity

### Test 2.1: Hash verification passes
1. Publish a test release on your fork with:
   - `RustPlusDesk-Setup.exe`
   - `RustPlusDesk-Setup.exe.sha256` (containing the SHA-256 hash)
2. Build the app, modify version to be lower than the test release
3. Click "Check for Updates"
4. **Expected**: Download succeeds, log shows `[update] Installer SHA-256 verified.`, installer starts without UAC prompt

### Test 2.2: Hash verification fails (tampered)
1. Publish a test release with a mismatched `.sha256` file
2. Click "Check for Updates"
3. **Expected**: Download succeeds, then message box shows integrity check failed, bad installer is deleted

### Test 2.3: Missing hash file
1. Publish a test release WITHOUT `.sha256`
2. Click "Check for Updates"
3. **Expected**: Log shows warning about missing hash file, but update proceeds (backward compat)

### Test 2.4: No UAC elevation
1. Install the app on a clean Windows VM
2. **Expected**: No UAC prompt during install (per-user install to `%LOCALAPPDATA%`)
3. Run auto-update
4. **Expected**: No UAC prompt when the new installer starts

---

## PR 3: DPAPI + OpenID + URI Hardening

### Test 3.1: profiles.json encrypted
1. Launch the app and add a server profile
2. Close the app
3. Open `%APPDATA%\RustPlusDesk\profiles.json` in a text editor
4. **Expected**: File contains binary data (DPAPI encrypted), NOT plaintext JSON
5. Relaunch the app
6. **Expected**: Profile loads correctly, decrypted transparently

### Test 3.2: profiles.json migration
1. Before testing, replace `%APPDATA%\RustPlusDesk\profiles.json` with an old plaintext JSON backup
2. Launch the app
3. **Expected**: App loads the plaintext profile, then on next save encrypts it
4. Check the file again — should now be binary

### Test 3.3: FCM config encrypted
1. Complete Steam login / FCM registration
2. Check `%APPDATA%\RustPlusDesk\`
3. **Expected**: `rustplusjs-config.json.enc` exists (encrypted)
4. `rustplusjs-config.json` should NOT exist while app is closed
5. While listener is running, `rustplusjs-config.json` may exist temporarily (decrypted for CLI)
6. Stop listener
7. **Expected**: Plaintext `rustplusjs-config.json` is deleted, only `.enc` remains

### Test 3.4: Steam OpenID verification
1. Click "Steam Login"
2. Complete login in browser
3. **Expected**: Login succeeds, SteamID64 is extracted
4. Check with a network proxy (e.g., Fiddler): app should POST back to `https://steamcommunity.com/openid/login` with `openid.mode=check_authentication`

### Test 3.5: OpenID CSRF protection
1. Start Steam login (browser opens)
2. Before completing, manually navigate to `http://127.0.0.1:PORT/steam/openid/return?openid.claimed_id=...&state=WRONG`
3. **Expected**: App rejects the callback with "OpenID state mismatch"

### Test 3.6: URI handler confirmation
1. Click a `rustplus://1.2.3.4:28082` link from outside the app (e.g., from a browser or Discord)
2. **Expected**: Message box appears asking to confirm pairing with unofficial server
3. Click "No"
4. **Expected**: Server is NOT added

---

## PR 4: Dependency + Misc Hardening

### Test 4.1: DevTools disabled in release
1. Build in Release mode: `dotnet build -c Release`
2. Launch the Release build
3. Right-click in a WebView2 (shop search or Steam login)
4. **Expected**: No "Inspect" option (DevTools disabled)
5. Build in Debug mode: `dotnet build -c Debug`
6. **Expected**: DevTools available in Debug

### Test 4.2: ZIP integrity check
1. Build the app
2. Launch and start the FCM listener
3. Check `%LOCALAPPDATA%\RustPlusDesk\runtime\rustplus-cli\.stamp`
4. **Expected**: Stamp file contains a 64-character SHA-256 hex string
5. Manually corrupt `rustplus-cli.zip` in the install directory
6. Relaunch and start listener
7. **Expected**: App detects hash mismatch and re-extracts the zip

---

## Regression Tests

### Test R.1: Existing functionality
1. Pair with a Rust server
2. Toggle smart switches
3. Receive smart alarm notifications
4. View the map with monuments
5. Use the shop search feature
6. **Expected**: All features work as before

### Test R.2: Single-instance pipe
1. Launch the app
2. Try launching a second instance with `rustplus://` argument
3. **Expected**: Second instance sends link to first instance via named pipe and exits

---

## Automation Notes

For CI/CD automation, consider:
- Unit tests for `OverlayLocalServer` (start/stop, upload/fetch, path traversal)
- Unit tests for `VerifyInstallerHashAsync` (mock HttpClient)
- Integration test for DPAPI round-trip (encrypt -> decrypt -> verify)
- Mock Steam OpenID verification endpoint

The WPF UI itself is harder to automate; the above manual E2E tests should be run before each release.
