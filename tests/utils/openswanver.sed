s/^Openswan [0-9]+\.[0-9]+\.[0-9]+.*/Openswan VERSION/
s/^Openswan nnB-.*/Openswan VERSION/
s/Openswan Version (.*); .*/Openswan Version VERSION/
s/Vendor ID .* pid:.*/Vendor ID THING pid:NUMBER/
s/started helper pid=.*$/started helper pid=PID /
s/Using 'no_kernel' interface code on .*/Using 'no_kernel' interface code on/

