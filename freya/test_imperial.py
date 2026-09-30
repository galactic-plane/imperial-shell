"""Unit tests for freya/imperial.py.

Third-party modules (open-interpreter, pygame, edge-tts, SpeechRecognition, colorama, requests)
are replaced with stubs, so the suite runs on any Python 3.9+ without the Freya venv and never
touches audio, the network, Ollama or the real system. Tests that need Windows PowerShell are
skipped when powershell.exe is unavailable.

    python -m unittest discover -s freya -p "test_*.py"
"""

import base64
import json
import os
import shutil
import subprocess
import sys
import tempfile
import types
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(HERE)


class _NoColour:
    def __getattr__(self, name):
        return ""


def _install_stubs():
    colorama = types.ModuleType("colorama")
    colorama.init = lambda **kwargs: None
    colorama.Fore = _NoColour()
    colorama.Style = _NoColour()

    interpreter_module = types.ModuleType("interpreter")
    interpreter_module.interpreter = types.SimpleNamespace(llm=types.SimpleNamespace(), messages=[])

    requests = types.ModuleType("requests")
    requests.get = mock.Mock(return_value=types.SimpleNamespace(status_code=200))

    stubs = {
        "colorama": colorama,
        "interpreter": interpreter_module,
        "requests": requests,
        "edge_tts": types.ModuleType("edge_tts"),
        "pygame": types.SimpleNamespace(mixer=mock.Mock()),
        "speech_recognition": types.SimpleNamespace(
            Recognizer=mock.Mock, Microphone=mock.Mock, WaitTimeoutError=Exception,
            UnknownValueError=Exception, RequestError=Exception),
    }
    sys.modules.update(stubs)


_install_stubs()
sys.path.insert(0, HERE)
import imperial  # noqa: E402

POWERSHELL = shutil.which("powershell.exe")


def make_shell(log_dir):
    with mock.patch.object(imperial, "LOG_DIR", log_dir), \
            mock.patch.dict(os.environ, {"FREYA_VOICE": "0"}), \
            mock.patch("builtins.print"):
        return imperial.ImperialShell()


class ShellTestCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.shell = make_shell(self._tmp.name)
        self.shell.speak = mock.Mock()

    def tearDown(self):
        self.shell.loop.close()
        self._tmp.cleanup()


class CommandCatalogueTests(ShellTestCase):
    def all_commands(self):
        return [(d, c) for menu in self.shell.command_menus.values() for d, c in menu]

    def test_every_category_has_a_menu(self):
        self.assertEqual(len(self.shell.menu_categories), 15)
        for key, _ in self.shell.menu_categories:
            self.assertIn(key, self.shell.command_menus)
            self.assertTrue(self.shell.command_menus[key])

    def test_counter_paths_use_single_backslashes(self):
        counters = [c for _, c in self.all_commands() if "Get-Counter" in c]
        self.assertTrue(counters)
        for command in counters:
            self.assertIn(r"'\Processor(_Total)\% Processor Time'", command)
            self.assertNotIn("\\\\", command)

    def test_no_variables_inside_single_quoted_strings(self):
        # PowerShell never expands $env:X or $(...) inside single quotes.
        for description, command in self.all_commands():
            for literal in command.split("'")[1::2]:
                self.assertNotIn("$env:", literal, description)
                self.assertNotIn("$(", literal, description)

    def test_confirmation_list_matches_real_commands(self):
        descriptions = {d for d, _ in self.all_commands()}
        self.assertTrue(self.shell.confirm_required)
        self.assertLessEqual(self.shell.confirm_required, descriptions)

    @unittest.skipUnless(POWERSHELL, "powershell.exe not available")
    def test_every_command_parses_in_windows_powershell(self):
        payload = json.dumps([c for _, c in self.all_commands()])
        script = (
            "$cmds = [Console]::In.ReadToEnd() | ConvertFrom-Json; $bad = @();"
            "foreach ($c in $cmds) { $t = $null; $e = $null;"
            "[void][System.Management.Automation.Language.Parser]::ParseInput($c, [ref]$t, [ref]$e);"
            "if ($e) { $bad += $c + ' => ' + $e[0].Message } };"
            "$bad -join [Environment]::NewLine"
        )
        result = subprocess.run(
            [POWERSHELL, "-NoProfile", "-NonInteractive", "-Command", script],
            input=payload, capture_output=True, text=True, encoding="utf-8", timeout=120)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "")


class ExecutionHelperTests(unittest.TestCase):
    def test_encoded_command_round_trips(self):
        command = "Get-Counter '\\Memory\\Available MBytes'; \"quoted\" $env:TEMP"
        decoded = base64.b64decode(imperial.encode_powershell_command(command)).decode("utf-16-le")
        self.assertTrue(decoded.endswith(command))
        self.assertIn("[Console]::OutputEncoding=[Text.Encoding]::UTF8", decoded)

    def test_argv_uses_sudo_only_when_not_elevated(self):
        elevated = imperial.build_command_argv("x", elevated=True, sudo_path="sudo.exe")
        self.assertEqual(elevated[0], "powershell.exe")
        via_sudo = imperial.build_command_argv("x", elevated=False, sudo_path="C:\\sudo.exe")
        self.assertEqual(via_sudo[:2], ["C:\\sudo.exe", "powershell.exe"])
        no_sudo = imperial.build_command_argv("x", elevated=False, sudo_path=None)
        self.assertEqual(no_sudo[0], "powershell.exe")
        self.assertIn("-EncodedCommand", no_sudo)
        self.assertIn("-NonInteractive", no_sudo)

    def test_clean_output_strips_utf16_residue(self):
        self.assertEqual(imperial.clean_output("S\x00c\x00a\x00n\x00\r\n"), "Scan\n")

    def test_truncate_keeps_the_tail(self):
        text = "a" * 50 + "VERDICT"
        truncated = imperial.truncate_for_prompt(text, limit=10)
        self.assertTrue(truncated.endswith("aaaVERDICT"))
        self.assertIn("47 earlier characters omitted", truncated)
        self.assertEqual(imperial.truncate_for_prompt("short", limit=10), "short")

    def test_run_streaming_captures_output_and_exit_code(self):
        echoed = []
        output, code, timed_out = imperial.run_streaming(
            [sys.executable, "-c", "print('alpha'); print('beta'); raise SystemExit(3)"],
            timeout=60, echo=echoed.append)
        self.assertEqual(output, "alpha\nbeta")
        self.assertEqual(echoed, ["alpha", "beta"])
        self.assertEqual(code, 3)
        self.assertFalse(timed_out)

    def test_run_streaming_kills_on_timeout(self):
        output, code, timed_out = imperial.run_streaming(
            [sys.executable, "-c", "import time; time.sleep(30)"], timeout=1, echo=None)
        self.assertTrue(timed_out)
        self.assertNotEqual(code, 0)

    @unittest.skipUnless(POWERSHELL, "powershell.exe not available")
    def test_encoded_command_runs_in_windows_powershell(self):
        argv = imperial.build_command_argv(
            "Write-Output \"caf\u00e9 $(1+1)\"; Write-Output 'done'", elevated=True, sudo_path=None)
        argv[0] = POWERSHELL
        output, code, timed_out = imperial.run_streaming(argv, timeout=120, echo=None)
        self.assertEqual(code, 0, output)
        self.assertEqual(output.splitlines(), ["caf\u00e9 2", "done"])


class ProtocolLaunchTests(unittest.TestCase):
    def test_protocol_scripts_exist_in_repository_layout(self):
        # setup-imperial-shell.ps1 installs them with the same relative paths next to imperial.py.
        for key, protocol in imperial.PROTOCOLS.items():
            self.assertTrue(os.path.isfile(os.path.join(REPO_ROOT, protocol["script"])), key)

    def test_launch_arguments(self):
        script, params = imperial.build_protocol_launch("C:\\Program Files\\Imp", "vader", ["-Level", "Audit"])
        self.assertEqual(script, os.path.join("C:\\Program Files\\Imp", "vader", "Invoke-ImperialMaintenance.ps1"))
        self.assertTrue(params.startswith("-NoExit -NoProfile -ExecutionPolicy Bypass -File "))
        self.assertIn('"C:\\Program Files\\Imp\\vader\\Invoke-ImperialMaintenance.ps1"', params)
        self.assertTrue(params.endswith("-Level Audit"))

    def test_missing_script_is_reported(self):
        with tempfile.TemporaryDirectory() as empty:
            ok, message = imperial.launch_protocol(empty, "windragon")
        self.assertFalse(ok)
        self.assertIn("Re-run setup-imperial-shell.ps1", message)

    @unittest.skipUnless(sys.platform == "win32", "Windows only")
    def test_elevated_launch_uses_runas(self):
        import ctypes
        with mock.patch.object(imperial, "is_admin", return_value=False), \
                mock.patch.object(ctypes.windll.shell32, "ShellExecuteW", return_value=42) as shell_execute:
            ok, _ = imperial.launch_protocol(REPO_ROOT, "vader", ["-Level", "Audit"])
        self.assertTrue(ok)
        _, verb, exe, params, workdir, show = shell_execute.call_args.args
        self.assertEqual(verb, "runas")
        self.assertEqual(exe, imperial.find_powershell())
        self.assertIn("-Level Audit", params)
        self.assertEqual(workdir, os.path.join(REPO_ROOT, "vader"))
        self.assertEqual(show, 1)

    @unittest.skipUnless(sys.platform == "win32", "Windows only")
    def test_declined_uac_is_reported(self):
        import ctypes
        with mock.patch.object(imperial, "is_admin", return_value=False), \
                mock.patch.object(ctypes.windll.shell32, "ShellExecuteW", return_value=5):
            ok, message = imperial.launch_protocol(REPO_ROOT, "windragon")
        self.assertFalse(ok)
        self.assertIn("denied", message)

    @unittest.skipUnless(sys.platform == "win32", "Windows only")
    def test_already_elevated_opens_new_console(self):
        with mock.patch.object(imperial, "is_admin", return_value=True), \
                mock.patch.object(imperial.subprocess, "Popen") as popen:
            ok, _ = imperial.launch_protocol(REPO_ROOT, "windragon")
        self.assertTrue(ok)
        self.assertEqual(popen.call_args.kwargs["creationflags"], subprocess.CREATE_NEW_CONSOLE)
        self.assertIn("winDragon.ps1", popen.call_args.args[0])

    def test_non_elevating_option_skips_uac(self):
        with mock.patch.object(imperial, "is_admin", return_value=False), \
                mock.patch.object(imperial.subprocess, "Popen") as popen:
            ok, _ = imperial.launch_protocol(REPO_ROOT, "vader", ["-ListTasks"], elevate=False)
        self.assertTrue(ok)
        popen.assert_called_once()


class MainMenuTests(ShellTestCase):
    def select(self, *answers):
        with mock.patch("builtins.input", side_effect=list(answers)), mock.patch("builtins.print"):
            return self.shell.get_main_menu_selection()

    def test_protocols_follow_the_categories(self):
        keys = self.shell.main_menu_keys()
        self.assertEqual(len(keys), 17)
        self.assertEqual(keys[15:], ["vader", "windragon"])

    def test_selection_maps_numbers_to_keys(self):
        self.assertEqual(self.select("1"), "system")
        self.assertEqual(self.select("16"), "vader")
        self.assertEqual(self.select("17"), "windragon")
        self.assertIsNone(self.select("18", "abc", "q"))

    def test_main_menu_lists_protocols(self):
        with mock.patch("os.system"), mock.patch("builtins.print") as printed:
            self.shell.show_main_menu()
        text = "\n".join(str(c.args[0]) for c in printed.call_args_list if c.args)
        self.assertIn("[16] Launch Vader - Imperial Maintenance Protocol", text)
        self.assertIn("[17] Launch WinDragon", text)

    def run_protocol_menu(self, key, *answers):
        with mock.patch("builtins.input", side_effect=list(answers)), mock.patch("builtins.print"), \
                mock.patch("os.system"), \
                mock.patch.object(imperial, "launch_protocol", return_value=(True, "launched")) as launch:
            self.shell.show_protocol_menu(key)
        return launch

    def test_vader_level_choice_is_passed_through(self):
        launch = self.run_protocol_menu("vader", "9", "1", "")
        launch.assert_called_once_with(imperial.APP_DIR, "vader", ["-Level", "Audit"], True)

    def test_vader_list_tasks_does_not_elevate(self):
        launch = self.run_protocol_menu("vader", "6", "")
        launch.assert_called_once_with(imperial.APP_DIR, "vader", ["-ListTasks"], False)

    def test_vader_back_launches_nothing(self):
        launch = self.run_protocol_menu("vader", "back")
        launch.assert_not_called()

    def test_windragon_launches_its_own_menu(self):
        launch = self.run_protocol_menu("windragon", "")
        launch.assert_called_once_with(imperial.APP_DIR, "windragon", [], True)


class RuntimeTests(ShellTestCase):
    def test_session_log_is_written(self):
        self.shell.log_runtime("hello", "INFO")
        with open(self.shell.runtime_log_file, encoding="utf-8") as f:
            self.assertIn("[INFO] hello", f.read())

    def test_text_mode_disables_audio(self):
        self.assertFalse(self.shell.audio_enabled)
        self.assertIsNone(self.shell.microphone)
        self.shell.play_login_music()
        self.assertFalse(self.shell.login_music_playing)

    def test_interpreter_is_not_given_os_control(self):
        llm = imperial.interpreter.llm
        self.assertEqual(llm.model, f"ollama/{imperial.MODEL}")
        self.assertFalse(imperial.interpreter.auto_run)
        self.assertFalse(getattr(imperial.interpreter, "os", False))
        self.assertIn("Never write or run code", imperial.interpreter.system_message)


if __name__ == "__main__":
    unittest.main()
