@echo off

set sender_file=small_test_file.txt
set receiver_file=..\receiver\output.txt

echo Comparing files...

fc "%sender_file%" "%receiver_file%"

if %errorlevel%==0 (
    echo Files are IDENTICAL.
) else (
    echo Files are DIFFERENT.
)

pause