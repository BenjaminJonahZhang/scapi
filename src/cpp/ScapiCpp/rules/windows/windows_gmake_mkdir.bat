@echo off
rem  This file is copyrighted, see copyright.txt

setlocal EnableDelayedExpansion

for %%f in ( %1 %2 %3 %4 %5 %6 %7 %8 %9 ) do (

    set parm=%%f

    set dir=!parm:/=\!

    if not exist !dir!   mkdir !dir!

)

