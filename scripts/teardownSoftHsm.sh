#!/bin/bash

export SOFTHSM2_CONF="/usr/share/softhsm/softhsm2.conf"

softhsm2-util --delete-token --token token-label --pin 1234 --so-pin 4321;
softhsm2-util --delete-token --token token-label2 --pin 1234 --so-pin 4321;

