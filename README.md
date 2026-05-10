## EdgeSavedPasswordsDumper (PowerShell)
*A small educational tool demonstrating that Edge stores credentials in cleartext in process memory.*

---

## Overview
PowerShell port of the original C# `EdgeSavedPasswordsDumper`. Walks committed
`PAGE_READWRITE` regions of root `msedge.exe` processes and regex-matches
saved-credential patterns. Same Win32 calls (`OpenProcess`, `VirtualQueryEx`,
`ReadProcessMemory`) wired up via `Add-Type` P/Invoke — single file, no compilation.

Intended for **educational and research purposes only**: memory inspection,
credential handling, and security design of password managers.

---

## Files
- `Dump-EdgePasswords.ps1` — the script.
- `Run.bat` — launches as the current user, bypassing ExecutionPolicy.
- `Run-AsAdmin.bat` — self-elevating launcher (UAC prompt). Required to read
  Edge processes belonging to **other users** on the machine.

---

## Running it (Windows blocks `.ps1` by default — pick one)

A vanilla Windows refuses to run `.ps1` files by double-click and ships with
`ExecutionPolicy = Restricted` for the user. None of the options below need a
permanent policy change.

### Option 1 — Double-click `Run.bat` *(easiest)*
Use this if you only need to read your own Edge processes.
- Right-click `Run-AsAdmin.bat` → **Run as administrator** to read every
  user’s Edge processes on the machine.

The `.bat` simply calls:
```
powershell.exe -NoProfile -ExecutionPolicy Bypass -File Dump-EdgePasswords.ps1
```
`-ExecutionPolicy Bypass` only affects that single invocation — system policy
is not changed.

### Option 2 — From an existing PowerShell window
```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Dump-EdgePasswords.ps1
```
Or, just for the current session:
```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\Dump-EdgePasswords.ps1
```

### Option 3 — One-liner without saving the file
```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "& { iex (Get-Content .\Dump-EdgePasswords.ps1 -Raw) }"
```

### Option 4 — Run straight from GitHub *(no clone, no download)*
The PowerShell equivalent of `curl https://… | python3` — fetch from raw GitHub
and pipe into `Invoke-Expression`. Paste into any PowerShell window:

```powershell
iex (irm 'https://raw.githubusercontent.com/kingdom84521/EdgeSavedPasswordsDumper/main/Dump-EdgePasswords.ps1')
```

Why this sidesteps the ExecutionPolicy problem from Options 1–3:
ExecutionPolicy only blocks `.ps1` **files on disk**. Code passed to
`Invoke-Expression` (`iex`) as a string is treated as interactive input — it
runs regardless of policy, even on `Restricted`. So no `-Bypass` flag needed.

**From cmd.exe / Win+R Run dialog** (no PowerShell window required):
```
powershell -NoProfile -Command "iex (irm 'https://raw.githubusercontent.com/kingdom84521/EdgeSavedPasswordsDumper/main/Dump-EdgePasswords.ps1')"
```

**To run as admin** (read every user’s Edge processes): open an elevated
PowerShell first (Win+X → *Terminal (Admin)* / *PowerShell (Admin)*), then
paste the one-liner. Self-elevating from inside a one-liner is doable but the
quoting gets ugly — opening an admin shell first is far cleaner.

**Notes / gotchas:**
- Use the **`raw.githubusercontent.com`** URL, not the repo blob page.
- On Windows PowerShell 5.1 GitHub requires TLS 1.2; if the fetch fails, prepend:
  ```powershell
  [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
  ```
  PowerShell 7+ doesn’t need this.
- For reproducibility/safety, pin to a commit SHA instead of `main`:
  ```
  https://raw.githubusercontent.com/<owner>/<repo>/<commit-sha>/Dump-EdgePasswords.ps1
  ```
- Replace `kingdom84521/EdgeSavedPasswordsDumper` with your fork’s
  `<owner>/<repo>` if you’ve forked.

### Option 5 — Permanent policy change (not recommended)
```powershell
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
```
Then `.\Dump-EdgePasswords.ps1` runs directly. Only do this if you understand
the implications — Options 1–4 are reversible per-invocation.

---

## Disclaimer
Provided **strictly for educational use**.

By using this project, you agree that:
- You are solely responsible for how you use this code.
- You will not use it to violate privacy, security policies, or any applicable laws.
- The author provides **no warranty** of any kind.
- The author **cannot be held liable** for any misuse, damage, or consequences resulting from this software.

---

## Requirements
- Windows with Edge (Chromium-based, v79+).
- Windows PowerShell 5.0+ (default on Windows 10/11) — PowerShell 7 also works.
- Without admin: only sees Edge processes ran by the current user.
- With admin: reads memory of every user's Edge processes on the machine.
