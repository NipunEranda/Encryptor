#!/bin/zsh

if [ "$1" = "build" ] && [ "$2" = "linux" ]; then
    python -m PyInstaller --onefile --noconsole --hidden-import=cryptography --icon=app.ico encryptor.py
elif [ "$1" = "clean" ]; then
    rm -r build
    rm -r dist
    rm Encryptor.spec
    rm -r .keys
fi