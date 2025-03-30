#!/usr/bin/env bash

base64 -d ./set_1/challenge_7.txt | openssl enc -d -nopad -aes-128-ecb -K $(echo -n "YELLOW SUBMARINE" | od -A n -t x1 | sed 's/ *//g')
