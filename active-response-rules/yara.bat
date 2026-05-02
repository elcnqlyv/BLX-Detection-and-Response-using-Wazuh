:: This script is meant to delete BLX Stealer and other malicious files matched by the YARA rules
@echo off
setlocal enableDelayedExpansion

:: Determine OS architecture
reg Query "HKLM\Hardware\Description\System\CentralProcessor<pre class="EnlighterJSRAW" data-enlighter-language="generic" data-enlighter-theme="" data-enlighter-highlight="" data-enlighter-linenumbers="" data-enlighter-lineoffset="" data-enlighter-title="" data-enlighter-group="">> Restart-Service -Name wazuh</pre>" | find /i "x86" > NUL && SET OS=32BIT || SET OS=64BIT
if %OS%==32BIT (
    SET log_file_path="%programfiles%\ossec-agent\active-response\active-responses.log"
)
if %OS%==64BIT (
    SET log_file_path="%programfiles(x86)%\ossec-agent\active-response\active-responses.log"
)

:: Read input from OSSEC agent
set input=
for /f "delims=" %%a in ('PowerShell -command "$logInput = Read-Host; Write-Output $logInput"') do (
    set input=%%a
)

:: File paths for operations
set json_file_path="C:\Program Files (x86)\ossec-agent\active-response\stdin.txt"
set yara_exe_path="C:\Program Files (x86)\ossec-agent\active-response\bin\yara\yara64.exe"
set yara_rules_path="C:\Program Files (x86)\ossec-agent\active-response\bin\yara\rules\yara_rules.yar"
set syscheck_file_path=
echo %input% > %json_file_path%
FOR /F "tokens=* USEBACKQ" %%F IN (`Powershell -Nop -C "(Get-Content 'C:\Program Files (x86)\ossec-agent\active-response\stdin.txt'|ConvertFrom-Json).parameters.alert.syscheck.path"`) DO (
SET syscheck_file_path=%%F
)

echo %syscheck_file_path% >> %log_file_path%


:: Perform YARA scan on the detected file
for /f "delims=" %%a in ('powershell -command "& \"%yara_exe_path%\" \"%yara_rules_path%\" \"%syscheck_file_path%\""') do (
    echo wazuh-yara: INFO - Scan result: %%a >> %log_file_path%

   :: Deleting the scanned file.
    del /f "%syscheck_file_path%"
    echo wazuh-yara: INFO - Successfully deleted: %%a >> %log_file_path%
)

exit /b