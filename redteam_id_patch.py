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
  - nxc module artifacts (nanodump, handlekatz, procdump, pi, impersonate,
    msol, keepass_trigger) — binary/script filenames and output names
"""

import os
import sys
import random
import string
import builtins
import functools

IDENT = os.environ.get('RTID', '')
_using_default = not IDENT
_confirmed = not _using_default  # explicit RTID needs no confirmation

if _using_default:
    IDENT = 'RedTeaming'

# Impacket files whose random.choice/sample calls generate on-disk forensic artifacts
_ARTIFACT_FILES = frozenset({
    'secretsdump.py',    # tmpFileName, __tmpServiceName, NTDS copy
    'serviceinstall.py', # service name, binary name
    'ldapattack.py',     # AD computer/user account names
    'rpcattack.py',      # temp name
    'smbattack.py',      # AD computer account name
})

# NXC module artifact overrides: module_name -> (attr, option_key, default_val, suffix)
_NXC_MODULE_ARTIFACTS = {
    'nanodump':        ('nano',                   'NANO_EXE_NAME',       'nano.exe',        '.exe'),
    'handlekatz':      ('handlekatz',             'HANDLEKATZ_EXE_NAME', 'handlekatz.exe',  '.exe'),
    'procdump':        ('procdump',               'PROCDUMP_EXE_NAME',   'procdump.exe',    '.exe'),
    'pi':              ('pi',                      None,                  'pi.exe',          '.exe'),
    'impersonate':     ('impersonate',             None,                  'Impersonate.exe', '.exe'),
    'msol':            ('msol',                    None,                  'msol.ps1',        '.ps1'),
    'keepass_trigger': ('remote_temp_script_path', None,                   None,              None),
}

# Modules with hardcoded artifact names in execute() command strings (not using self.<attr>)
_NXC_HARDCODED_EXEC = {
    'pi':          'pi.exe',
    'impersonate': 'Impersonate.exe',
    'msol':        'msol.ps1',
}


def _ensure_confirmed():
    """Prompt once for default-ident confirmation, only when patching fires."""
    global _confirmed
    if _confirmed:
        return
    _confirmed = True  # before prompt to prevent re-entry
    print(f"[RT-ID] WARNING: RTID not set.", file=sys.stderr)
    try:
        resp = input(f"[RT-ID] Continue with default ident '{IDENT}'? [Y/n] ")
        if resp.strip().lower() == 'n':
            print("[RT-ID] Aborted. Set RTID and retry.", file=sys.stderr)
            sys.exit(1)
    except Exception:
        pass  # Non-interactive — proceed with default
    print(f"[RT-ID] Active: ident={IDENT}", file=sys.stderr)

# Populations whose random calls we intercept in artifact files
_HOOKED_POPULATIONS = (string.ascii_letters, string.ascii_lowercase, string.ascii_uppercase)

# Functions inside _ARTIFACT_FILES whose random calls are network-level, not artifacts
_PASSTHROUGH_FUNCS = frozenset({
    'createPartialTGT',  # secretsdump.py: Kerberos ticket keyvalue
})

# ── Hook 1: random.choice ────────────────────────────────────────────
_orig_choice = random.choice


def _hooked_choice(population):
    if population in _HOOKED_POPULATIONS:
        caller_file = os.path.basename(sys._getframe(1).f_code.co_filename)
        if caller_file not in _ARTIFACT_FILES:
            return _orig_choice(population)
        if sys._getframe(2).f_code.co_name in _PASSTHROUGH_FUNCS:
            return _orig_choice(population)
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
    if population in _HOOKED_POPULATIONS:
        caller_file = os.path.basename(sys._getframe(1).f_code.co_filename)
        if caller_file not in _ARTIFACT_FILES:
            return _orig_sample(population, k, *args, **kwargs)
        if sys._getframe(2).f_code.co_name in _PASSTHROUGH_FUNCS:
            return _orig_sample(population, k, *args, **kwargs)
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
            _ensure_confirmed()
            return IDENT
        def __repr__(self):
            _ensure_confirmed()
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
        _ensure_confirmed()
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
        _ensure_confirmed()
        return IDENT
    mod.gen_random_string = _ident_gen
    return True


# ── NXC module artifact patches ──────────────────────────────────────

def _apply_nxc_module_patch(module):
    """Patch NXC module artifact filenames to use IDENT."""
    name = getattr(module, 'name', None)
    if name not in _NXC_MODULE_ARTIFACTS:
        return
    _ensure_confirmed()
    attr, option_key, default_val, suffix = _NXC_MODULE_ARTIFACTS[name]

    # keepass_trigger: full path override
    if name == 'keepass_trigger':
        setattr(module, attr, 'C:\\Windows\\Temp\\' + IDENT + '.ps1')
        return

    # Skip attribute override if user customized via module option
    user_customized = option_key and getattr(module, attr, None) != default_val

    if not user_customized:
        new_name = IDENT + suffix
        setattr(module, attr, new_name)
    else:
        new_name = getattr(module, attr)

    # Wrap on_admin_login for modules with hardcoded filenames in command strings
    if name in _NXC_HARDCODED_EXEC and not user_customized:
        old_name = _NXC_HARDCODED_EXEC[name]
        _orig_oal = module.on_admin_login

        @functools.wraps(_orig_oal)
        def _wrapped_oal(context, connection, _orig=_orig_oal,
                         _old=old_name, _new=new_name):
            _real_exec = connection.execute
            def _replace_exec(cmd, *a, **kw):
                return _real_exec(cmd.replace(_old, _new), *a, **kw)
            connection.execute = _replace_exec
            try:
                return _orig(context, connection)
            finally:
                connection.execute = _real_exec

        module.on_admin_login = _wrapped_oal

    # Wrap on_admin_login for nanodump: patch datetime to control output log name
    if name == 'nanodump':
        _orig_oal_nano = module.on_admin_login
        _nano_globals = type(module).on_admin_login.__globals__

        class _IdentDate:
            """Fake date whose strftime() returns IDENT."""
            def strftime(self, fmt):
                return IDENT

        class _IdentDatetime:
            """Fake datetime class: today() returns _IdentDate, now() delegates."""
            @classmethod
            def today(cls):
                return _IdentDate()
            @classmethod
            def now(cls):
                import datetime as _dt
                return _dt.datetime.now()

        @functools.wraps(_orig_oal_nano)
        def _wrapped_nano_oal(context, connection, _orig=_orig_oal_nano,
                              _g=_nano_globals, _fake=_IdentDatetime):
            _real_dt = _g['datetime']
            _g['datetime'] = _fake
            try:
                return _orig(context, connection)
            finally:
                _g['datetime'] = _real_dt

        module.on_admin_login = _wrapped_nano_oal


def _patch_nxc_moduleloader(mod):
    """Wrap ModuleLoader.init_module() to patch module artifacts after options().
    Returns True if patch applied, False if module not ready yet."""
    if not hasattr(mod, 'ModuleLoader'):
        return False
    _orig_init_mod = mod.ModuleLoader.init_module
    if getattr(_orig_init_mod, '_rtid_patched', False):
        return True

    @functools.wraps(_orig_init_mod)
    def _patched_init_mod(self, module_path):
        module = _orig_init_mod(self, module_path)
        if module is not None:
            _apply_nxc_module_patch(module)
        return module

    _patched_init_mod._rtid_patched = True
    mod.ModuleLoader.init_module = _patched_init_mod
    return True


# ── Hook 4: unified __import__ wrapper for all post-import patches ───
_lib_patches = {
    'impacket.examples.secretsdump': _patch_secretsdump,
    'nxc.helpers.misc': _patch_nxc_misc,
    'nxc.loaders.moduleloader': _patch_nxc_moduleloader,
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
            _ensure_confirmed()
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
            _ensure_confirmed()
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
if not _using_default:
    print(f"[RT-ID] Active: ident={IDENT}", file=sys.stderr)
