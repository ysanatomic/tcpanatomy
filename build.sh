#!/bin/bash

gcc -Wall -c packets.c
gcc -Wall -c tcpanatomy.c

gcc -o tcpanatomy tcpanatomy.o packets.o
