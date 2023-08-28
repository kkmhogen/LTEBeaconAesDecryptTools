@echo off

echo path:%~dp0

set base=%~dp0

set class=%base%\aestools
set libs=%base%\..\lib

set class_path=%class%;;

java -classpath %class_path% aestools.AesTest

