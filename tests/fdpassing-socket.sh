#!/bin/sh

if test -e a.sock; then
    rm -f a.sock
fi

./fdpassing$EXEEXT --server --socketname a.sock 2>/dev/null &
SERVER_PID=$!

# Wait for server stats up
sleep 1

./fdpassing$EXEEXT --socketname file://a.sock
STATUS=$?

if test $STATUS -eq 0; then
    exit 0
else
    kill $SERVER_PID
    exit $STATUS
fi
rm -f a.sock
