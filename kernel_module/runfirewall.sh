#!/bin/bash

make clean -j20 && make all -j20
sudo rmmod myfirewall.ko 
sudo insmod myfirewall.ko
