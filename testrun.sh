#!/bin/bash

unbound-anchor -a root.key
unbound -dvc unboundtest.conf

