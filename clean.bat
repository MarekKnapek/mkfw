@if "%~1"=="inner" goto :mk_inner
@cmd.exe /c ""%~f0" "inner" %*"
@if %errorlevel% neq 0 goto :mk_outer_bad
@goto :mk_outer_gud

:mk_inner
@echo off
call :mk_delete "%~dp0memclr_amd64.obj" || goto :mk_bad
call :mk_delete "%~dp0memclr_i386.obj" || goto :mk_bad
call :mk_delete "%~dp0memcpy_amd64.obj" || goto :mk_bad
call :mk_delete "%~dp0memcpy_i386.obj" || goto :mk_bad
call :mk_delete "%~dp0mkfw.amd64.exe" || goto :mk_bad
call :mk_delete "%~dp0mkfw.exe" || goto :mk_bad
call :mk_delete "%~dp0mkfw.i386.exe" || goto :mk_bad
call :mk_delete "%~dp0mkfw.obj" || goto :mk_bad
call :mk_delete "%~dp0wcslen_amd64.obj" || goto :mk_bad
call :mk_delete "%~dp0wcslen_i386.obj" || goto :mk_bad
call :mk_delete "%~dp0wcsncmp_amd64.obj" || goto :mk_bad
call :mk_delete "%~dp0wcsncmp_i386.obj" || goto :mk_bad
goto :mk_gud

:mk_delete
del "%~1"
if exist "%~1" goto :mk_del_failed
goto :mk_gud

:mk_del_failed
echo Could not delete file: `%~1'.
goto :mk_fail

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
