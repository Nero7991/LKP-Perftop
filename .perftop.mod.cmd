cmd_/home/ocollaco/proj3/perftop/perftop.mod := printf '%s\n'   perftop.o | awk '!x[$$0]++ { print("/home/ocollaco/proj3/perftop/"$$0) }' > /home/ocollaco/proj3/perftop/perftop.mod
