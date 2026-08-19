"""Subprocess helpers that never flash a console window on Windows."""
import subprocess


def run_hidden(args, timeout=None, env=None, encoding=None):
    startupinfo = None
    creationflags = 0
    if hasattr(subprocess, "STARTUPINFO"):
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        startupinfo.wShowWindow = subprocess.SW_HIDE
        creationflags = subprocess.CREATE_NO_WINDOW

    return subprocess.run(
        args,
        capture_output=True,
        text=True,
        timeout=timeout,
        startupinfo=startupinfo,
        creationflags=creationflags,
        env=env,
        encoding=encoding,
        # Localised Windows tools emit text in the console codepage, which
        # doesn't always match what Python expects. Replacing undecodable
        # bytes keeps a stray character from failing the whole check.
        errors="replace",
    )


def run_powershell(script, timeout=None, env=None):
    """Run a PowerShell script hidden, with UTF-8 output on both sides.

    Without pinning the encoding, non-ASCII output (localised error text,
    Thai machine descriptions) decodes as mojibake and can break the JSON
    the callers parse.
    """
    preamble = "[Console]::OutputEncoding = [System.Text.Encoding]::UTF8\n"
    return run_hidden(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", preamble + script],
        timeout=timeout,
        env=env,
        encoding="utf-8",
    )
