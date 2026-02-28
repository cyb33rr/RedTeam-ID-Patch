"""RedTeam ID Patch — Forensic Identifier Monkey Patcher.

Loaded via redteam_id_patch.pth at Python startup. Replaces all random/hardcoded
forensic identifiers in Impacket and NetExec with the **full** RTID
string (default: RedTeaming). Warns interactively when RTID is unset.

Patched traces:
  - random.choice(string.ascii_letters) -> full IDENT on first iter, '' after
  - random.sample(string.ascii_letters, k) -> [IDENT] + [''] * (k-1)
  - wmiexec OUTPUT_FILENAME (time.time based)
  - dcomexec OUTPUT_FILENAME (__main__ overwrite after [:5] slice)
  - psexec RemCom pipe names
  - secretsdump hardcoded __output / execute.bat
  - nxc gen_random_string() -> always full IDENT
"""

import os
import sys
import random
import string
import builtins
import functools

IDENT = os.environ.get('RTID', '')
if not IDENT:
    IDENT = 'RedTeaming'
    print(f"[RT-ID] WARNING: RTID not set.", file=sys.stderr)
    try:
        resp = input(f"[RT-ID] Continue with default ident '{IDENT}'? [Y/n] ")
        if resp.strip().lower() == 'n':
            print("[RT-ID] Aborted. Set RTID and retry.", file=sys.stderr)
            sys.exit(1)
    except Exception:
        pass  # Non-interactive or replaced stdin — proceed with default

# ── Hook 1: random.choice ────────────────────────────────────────────
_orig_choice = random.choice


def _hooked_choice(population):
    if population is string.ascii_letters or population == string.ascii_letters:
        frame = sys._getframe(1)
        idx = frame.f_locals.get('i', frame.f_locals.get('_', None))
        if isinstance(idx, int):
            return IDENT if idx == 0 else ''
        return IDENT[0]  # standalone call (not in comprehension)
    return _orig_choice(population)


random.choice = _hooked_choice

# ── Hook 2: random.sample ────────────────────────────────────────────
_orig_sample = random.sample


def _hooked_sample(population, k, *args, **kwargs):
    if population is string.ascii_letters or population == string.ascii_letters:
        if k <= 0:
            return []
        return [IDENT] + [''] * (k - 1)
    return _orig_sample(population, k, *args, **kwargs)


random.sample = _hooked_sample

# ── Hook 3: wmiexec / dcomexec OUTPUT_FILENAME via time.time ─────────
_script = os.path.basename(sys.argv[0]) if sys.argv else ''

if _script == 'wmiexec.py':
    import time as _time_mod
    _orig_time = _time_mod.time

    class _IdentTime(float):
        """Float subclass whose str()/repr() returns the ident string."""
        def __str__(self):
            return IDENT
        def __repr__(self):
            return IDENT

    _time_mod.time = lambda: _IdentTime(_orig_time())


# ── Post-import patch functions ───────────────────────────────────────

def _patch_secretsdump(mod):
    """Patch RemoteOperations hardcoded __output and execute.bat.
    Returns True if patch applied, False if module not ready yet."""
    if not hasattr(mod, 'RemoteOperations'):
        return False
    _orig_init = mod.RemoteOperations.__init__
    if getattr(_orig_init, '_rtid_patched', False):
        return True  # already wrapped — avoid double-wrap / infinite recursion

    @functools.wraps(_orig_init)
    def _patched_init(self, *a, **kw):
        _orig_init(self, *a, **kw)
        self._RemoteOperations__batchFile = '%TEMP%\\' + IDENT + '.bat'
        self._RemoteOperations__output = '%SYSTEMROOT%\\Temp\\' + IDENT

    _patched_init._rtid_patched = True
    mod.RemoteOperations.__init__ = _patched_init
    return True


def _patch_nxc_misc(mod):
    """Replace nxc.helpers.misc.gen_random_string with ident version.
    Returns True if patch applied, False if module not ready yet."""
    if not hasattr(mod, 'gen_random_string'):
        return False
    def _ident_gen(length=10):
        return IDENT  # always full string, ignore length
    mod.gen_random_string = _ident_gen
    return True


# ── Hook 4: unified __import__ wrapper for all post-import patches ───
_lib_patches = {
    'impacket.examples.secretsdump': _patch_secretsdump,
    'nxc.helpers.misc': _patch_nxc_misc,
}
_psexec_done = _script != 'psexec.py'
_dcomexec_done = _script != 'dcomexec.py'
_orig_import = builtins.__import__


def _master_import(name, *args, **kwargs):
    global _psexec_done, _dcomexec_done
    result = _orig_import(name, *args, **kwargs)

    # Library module patches (secretsdump, nxc misc)
    # Only remove from dict if patch returns True (module fully loaded)
    for mod_name in list(_lib_patches):
        patch_fn = _lib_patches.get(mod_name)
        if patch_fn and mod_name in sys.modules:
            if patch_fn(sys.modules[mod_name]):
                _lib_patches.pop(mod_name, None)

    # psexec RemCom pipe name patches
    if not _psexec_done:
        m = sys.modules.get('__main__')
        if m and hasattr(m, 'RemComSTDOUT'):
            m.RemComSTDOUT = IDENT + '_stdout'
            m.RemComSTDIN = IDENT + '_stdin'
            m.RemComSTDERR = IDENT + '_stderr'
            # Wrap openPipe to catch hardcoded RemCom_communicaton string
            if hasattr(m, 'PSEXEC') and hasattr(m.PSEXEC, 'openPipe'):
                _orig_op = m.PSEXEC.openPipe

                def _patched_openPipe(self, s, tid, pipe, access, _real=_orig_op):
                    if isinstance(pipe, str) and 'RemCom_communicaton' in pipe:
                        pipe = pipe.replace('RemCom_communicaton', IDENT + '_comm')
                    return _real(self, s, tid, pipe, access)

                m.PSEXEC.openPipe = _patched_openPipe
            _psexec_done = True

    # dcomexec OUTPUT_FILENAME patch (overwrite after [:5] truncation)
    if not _dcomexec_done:
        m = sys.modules.get('__main__')
        if m and hasattr(m, 'OUTPUT_FILENAME'):
            m.OUTPUT_FILENAME = '__' + IDENT
            _dcomexec_done = True

    # Uninstall wrapper once all patches are applied
    if not _lib_patches and _psexec_done and _dcomexec_done:
        builtins.__import__ = _orig_import

    return result


builtins.__import__ = _master_import

# Patch any modules that were already loaded before the hook
for _mn in list(_lib_patches):
    if _mn in sys.modules:
        if _lib_patches[_mn](sys.modules[_mn]):
            del _lib_patches[_mn]
try:
    del _mn  # avoid leaking loop var into module scope
except NameError:
    pass

# ── Startup banner ────────────────────────────────────────────────────
print(f"[RT-ID] Active: ident={IDENT}", file=sys.stderr)
