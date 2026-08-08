@echo off
REM Cryptenium end-to-end test suite (Windows / cmd).
REM Runs in an isolated test home so the real user vault is never touched.
setlocal
set "FAILED=0"

if "%1"=="" ( set "EXE=..\build\cryptenium.exe" ) else ( set "EXE=%1" )
if not exist "%EXE%" ( echo ERROR: executable not found: %EXE% & exit /b 1 )

set "TESTHOME=%CD%\testhome"
if exist "%TESTHOME%" rmdir /s /q "%TESTHOME%"
mkdir "%TESTHOME%"
set "USERPROFILE=%TESTHOME%"

echo === 1. init (expect success) ===
(echo secret123 & echo secret123) | "%EXE%" init >nul 2>&1
if errorlevel 1 ( echo FAIL: init & set /a FAILED+=1 ) else ( echo PASS )

echo === 2. init again (expect already exists, exit 0) ===
(echo secret123 & echo secret123) | "%EXE%" init >nul 2>&1
if errorlevel 1 ( echo FAIL: init-again & set /a FAILED+=1 ) else ( echo PASS )

echo === 3. add github (expect success) ===
echo secret123 | "%EXE%" add --service github --username alice --password hunter2 >nul 2>&1
if errorlevel 1 ( echo FAIL: add & set /a FAILED+=1 ) else ( echo PASS )

echo === 4. add gmail generated (expect success) ===
echo secret123 | "%EXE%" add --service gmail --username bob --generate --length 20 --symbols >nul 2>&1
if errorlevel 1 ( echo FAIL: add-gen & set /a FAILED+=1 ) else ( echo PASS )

echo === 5. list contains both entries ===
echo secret123 | "%EXE%" list > list_test.txt 2>&1
findstr /c:"github (alice)" list_test.txt >nul && findstr /c:"gmail (bob)" list_test.txt >nul
if errorlevel 1 ( echo FAIL: list & set /a FAILED+=1 ) else ( echo PASS )

echo === 6. wrong password rejected ===
echo nope | "%EXE%" list >nul 2>&1
if not errorlevel 1 ( echo FAIL: wrong-password & set /a FAILED+=1 ) else ( echo PASS )

echo === 7. delete github confirmed (expect success) ===
(echo secret123 & echo y) | "%EXE%" delete --service github --username alice >nul 2>&1
if errorlevel 1 ( echo FAIL: delete-y & set /a FAILED+=1 ) else ( echo PASS )

echo === 8. delete gmail cancelled (expect no delete) ===
(echo secret123 & echo n) | "%EXE%" delete --service gmail --username bob >nul 2>&1
if errorlevel 1 ( echo FAIL: delete-n & set /a FAILED+=1 ) else ( echo PASS )

echo === 9. generate (expect success) ===
"%EXE%" generate --length 24 --symbols >nul 2>&1
if errorlevel 1 ( echo FAIL: generate & set /a FAILED+=1 ) else ( echo PASS )

echo === 10. version (expect success) ===
"%EXE%" version >nul 2>&1
if errorlevel 1 ( echo FAIL: version & set /a FAILED+=1 ) else ( echo PASS )

echo.
if "%FAILED%"=="0" ( echo ALL TESTS PASSED ) else ( echo %FAILED% TESTS FAILED )
del /q list_test.txt 2>nul
exit /b %FAILED%
