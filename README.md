# RedTeam ID Patch

Monkey-patch hook that replaces all random/hardcoded forensic identifiers in **Impacket** and **NetExec** with a controlled identification string. Activates automatically at Python startup via a `.pth` file — no code changes to the target tools required.

## Install

```bash
# From a local clone (inside your Impacket/NetExec venv):
pip install .

# Or directly from GitHub:
pip install git+https://github.com/cyb33rr/RedTeam-ID-Patch.git
```

## Usage

```bash
# Set your team identifier:
export RTID=myteam

# Then use Impacket / NetExec as normal:
wmiexec.py DOMAIN/user:pass@target
secretsdump.py DOMAIN/user:pass@target
nxc smb target -u user -p pass --sam
```

If `RTID` is not set, the hook defaults to `RedTeaming` and prompts for confirmation.

On startup you'll see:
```
[RT-ID] Active: ident=myteam
```

## What Gets Patched

| Tool / Module | Artifact | Default Value | Patched To |
|---|---|---|---|
| **Impacket (general)** | `random.choice(ascii_letters)` filenames | Random 8-char string | `RTID` |
| **Impacket (general)** | `random.sample(ascii_letters, k)` filenames | Random k-char string | `RTID` |
| **wmiexec.py** | `OUTPUT_FILENAME` (via `time.time()`) | Epoch timestamp | `RTID` |
| **dcomexec.py** | `OUTPUT_FILENAME` | Random `__` + 5 chars | `__` + `RTID` |
| **psexec.py** | `RemComSTDOUT/IN/ERR` pipe names | `RemCom_stdout` etc. | `RTID_stdout` etc. |
| **psexec.py** | `RemCom_communicaton` pipe | Hardcoded string | `RTID_comm` |
| **secretsdump.py** | `__output` temp file | `__output` | `RTID` |
| **secretsdump.py** | `execute.bat` batch file | `execute.bat` | `RTID.bat` |
| **NetExec** | `gen_random_string()` | Random string | `RTID` |

## Supported Tools

- Impacket: `wmiexec.py`, `smbexec.py`, `atexec.py`, `dcomexec.py`, `psexec.py`, `secretsdump.py`
- NetExec (nxc): all modules using `gen_random_string()`

## Uninstall

```bash
pip uninstall redteam-id-patch
```

This cleanly removes both `redteam_id_patch.py` and `redteam_id_patch.pth` from `site-packages`.
