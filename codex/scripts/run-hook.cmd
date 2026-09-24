@echo off
rem Runs one Codex hook event (%1) through AgentGuards on Windows.
rem Codex runs Windows hook commands with cmd.exe, which cannot run the Unix-style
rem Python command, so on Windows the hooks run inside the AgentGuards CLI
rem (agentguards.exe), installed by the AgentGuards installer.
setlocal
set "AG=%USERPROFILE%\.agentguards\bin\agentguards.exe"
if exist "%AG%" goto check
for %%I in (agentguards.exe) do set "AG=%%~$PATH:I"
if defined AG if exist "%AG%" goto check
goto missing
:check
rem Too old to run hooks (CLI 0.1.0 had none)? Treat it as missing.
"%AG%" hook --supports codex >nul 2>&1 || goto missing
"%AG%" hook codex %1
exit /b %ERRORLEVEL%
:missing
rem Fail-closed, like the Python hook when AgentGuards is not configured.
rem The | below is inside a JSON string, i.e. inside quotes, where cmd.exe prints it literally.
if /i "%~1"=="UserPromptSubmit" (
  echo {"decision":"block","reason":"AgentGuards on Windows needs the AgentGuards CLI (0.2 or newer) to run its Codex hooks. Install or update it in PowerShell with: irm https://github.com/alelaguard/agentguards-plugins/releases/latest/download/install.ps1 | iex"}
  exit /b 0
)
if /i "%~1"=="PreToolUse" (
  echo {"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"AgentGuards on Windows needs the AgentGuards CLI (0.2 or newer) to run its Codex hooks. Install or update it in PowerShell with: irm https://github.com/alelaguard/agentguards-plugins/releases/latest/download/install.ps1 | iex"}}
  exit /b 0
)
exit /b 0
