#!/bin/sh

# set some funky toilet options
toilet_options=
[ -t 0 ] && toilet_options="--metal --width $(tput cols) --font future"

# use tilet if possible
if which toilet >/dev/null
then
    header() {
        toilet $toilet_options $@
    }
else
    header() {
        figlet -t $@
    }
fi

set -e && make programs

rm -f */core

for f in $(make testlist)
do
    (cd $f; header $f; rm -f core;
     make pcapupdate
     while ! make check && ! [ -f core ];
     do
         make update && git add -p .
     done
    )
done

if [ -f */core ]; then
   exit 10
fi
