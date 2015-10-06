@echo off
rem  This file is copyrighted, see copyright.txt

setlocal

if not "%:~2%" == "" goto doit

:error

echo windows_gmake_cp.bat:  error:  expected exactly 2 parameters
goto done

:doit
    
if not "%3%4%5%6%8%9" == "" goto error

set input1=%1
set output1=%2

set input=%input1:/=\%
set output=%output1:/=\%

move /y %input% %output%



:done
