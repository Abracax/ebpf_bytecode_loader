#!/bin/bash

USAGE="Usage (needs sudo): $0 EBPF_SRC_PATH EBPF_MAIN_SECTION [FILTER_BYTES_EXTRACTOR_PATH]\n"
OBJ=filter

if [ "$#" -eq 3 ] ;then 
    if [ ! -f "$3" ]; then
        printf "Extractor binary invalid!"
        printf "%b" "${USAGE}" >&2
        exit 1
    fi
    clang -O2 -emit-llvm -c $1 -o - | 
        llc-10 -march=bpf -filetype=obj -o ${OBJ};

    ./$3 ${OBJ} $2;
elif [ "$#" -eq 2 ] ;then 
    clang -O2 -emit-llvm -c $1 -o - | 
        llc-10 -march=bpf -filetype=obj -o ${OBJ};
else
    printf "%b" "${USAGE}" >&2
    exit 1
fi

