# deadmans-switch
a deadmans switch in go that encrypt ur files with aes256 gcm and encrypts the extracted aes key with rsa


setup:
in your folder: mkdir keys
run genkeys to get your rsa key pair, isolate the private that will be used to get your files back. (private  will be stored on another drive)
you can then compile the main with the path you changed. --> go build "file.go"
then go in your settings and assign the keyboard shortcut u want to launch the compiled file
