@if "%~1"=="inner" goto :mk_inner
@cmd.exe /c ""%~f0" "inner" %*"
@if %errorlevel% neq 0 goto :mk_outer_bad
@goto :mk_outer_gud

:mk_inner
@echo off
call "%~dp0build.amd64.bat" || goto :mk_bad
call "%~dp0build.i386.bat" || goto :mk_bad
goto :mk_gud

:mk_fail
exit /b 1
goto :mk_end

:mk_bad
exit /b %errorlevel%
goto :mk_end

:mk_gud
goto :mk_end

:mk_outer_bad
@echo Bad.
@exit /b %errorlevel%
@goto :mk_end

:mk_outer_gud
@echo Gud.
@goto :mk_end

:mk_end
