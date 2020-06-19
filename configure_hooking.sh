#!/usr/bin/env bash

virtualenv --python=$(which python3) ./venv
./venv/bin/pip install -r ./requirements.txt

source venv/bin/activate
