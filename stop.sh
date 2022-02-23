#!/usr/bin/env bash
# https://growingsaja.tistory.com/330

stop_target=`ps -ef | grep waitress-serve | awk '{print$2}'`

for each_target in $stop_target; do
    kill -9 $each_target
done
