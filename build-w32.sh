#!/bin/sh

[ -z "$w32root" ] && w32root="$HOME/w32root"

 ./configure --enable-maintainer-mode --prefix=${w32root}  \
             --host=i586-mingw32msvc --build=`./config.guess` 

 
	     
 
