@echo off
rem
rem  This script expects 2 parameters:  the basename of a source file and the object directory.
rem  If it is not empty, the object directory name must end in / -- not \, /!
rem
rem  The script assumes that directory .make exists and contains the file
rem  %1.log which is the output of the cl.exe compiler executed like this:
rem
rem     cl   /showIncludes >.make\%1.log [other options]
rem
rem  This script creates .make\%1.d and deletes %1.log
rem
rem

setlocal EnableDelayedExpansion

echo %2%1.obj .make/%1.d: \>.make/%1.d

find "Note: including file:" .make\%1.log >.make\%1.log.1
find /i /v "microsoft visual studio" .make\%1.log.1 >.make\%1.log.2
find /i /v "vc\include" .make\%1.log.2 >.make\%1.log.3
find /i /v "microsoft sdks" .make\%1.log.3 >.make\%1.log.4


for /F "usebackq delims= skip=8"  %%a in ( .make\%1.log.4 ) do @( 

   set cl=%%a

   set n1=!cl:Note: including file:=!


   rem
   rem  gnu make doesn't like backslashes and works fine with forward slashs
   rem  so turn all backslashes into forward slashes.
   rem

   set n2=!n1:\=/!

   rem
   rem  remove redundant spaces in the names.  We should not really being doing
   rem  this!  BUT, the output from compiler /showInclueds option has leading spaces
   rem  that need to be removed, and we only have a replace-all feature available to
   rem  us.  So we are going to hope that nobody in their right mind would created
   rem  directories with MULTIPLE SPACES IN A ROW in the name...
   rem


   set n2a=!n2:          = !
   set n2b=!n2a:         = !
   set n2c=!n2b:        = !
   set n2d=!n2c:        = !
   set n2e=!n2d:       = !
   set n2f=!n2e:      = !
   set n2g=!n2f:     = !
   set n2h=!n2g:    = !
   set n2i=!n2h:   = !

   rem
   rem  Now remove leading spaces on the included file names
   rem
   rem  first handle the output format if the /Zi option is
   rem  used

   set n2j=!n2i: c:=c:!
   set n2k=!n2j: c:=c:!

   rem
   rem  Now handle the compiler's /showIncludes output format if
   rem  /Zi is not used.  Sigh.
   rem

   set n2l=!n2k: .=.!
   set n2m=!n2l: .=.!

   rem 
   rem  now replace all remaining spaces (which should only be in
   rem  file names) with "\ "
   rem

   set nm=!n2m: =\ !

   rem
   rem  put a gnu make line continuation character on the end of the line...
   rem


   echo !nm!  \

)  >>.make\%1.d

echo # >>.make\%1.d

del .make\%1.log.1
del .make\%1.log.2
del .make\%1.log.3
del .make\%1.log.4
del .make\%1.log



