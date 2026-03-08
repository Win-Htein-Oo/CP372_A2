@echo off

echo Comparing files (binary mode)...

fc /b Sender\small_test_file.txt Receiver\output.txt

if %errorlevel%==0 (
    echo.
    echo SUCCESS: Files match exactly.
) else (
    echo.
    echo ERROR: Files do not match.
)

fc /b Sender\large_test_file.txt Receiver\output.txt

if %errorlevel%==0 (
    echo.
    echo SUCCESS: Files match exactly.
) else (
    echo.
    echo ERROR: Files do not match.
)

pause