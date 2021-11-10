#!/bin/bash

if [ "$#" -ne   2 ]
then 
    echo "$0 <ebpf source code path> <ebpf main section name>"
    exit
fi

OBJ=$(echo $1| cut -d'.' -f 1);

rm ${OBJ} filter_gen;

clang -O2 -emit-llvm -c $1 -o - | llc -march=bpf -filetype=obj -o ${OBJ};
gcc -g -Wall -o filter_gen filter_gen.c main.c -lelf;

./filter_gen ${OBJ} $2;
