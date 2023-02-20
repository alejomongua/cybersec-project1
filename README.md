# Digital signatures lab

Implementación de firmas DSA como primer proyecto del curso de cyberseguridad 2023-1 UNAL

En el archivo dsa.py se implementan las siguientes funciones:

## `generate_keypair`

Genera un par de llaves: llave pública y llave privada (retornadas en ese orden). Recibe un argumento opcional que corresponde la passphrase que protegerá la llave privada

##  `sign_message`, `sign_file`

Reciben un mensaje o la ruta a un archivo respectivamente, la llave privada y opcionalmente la passphrase de la llave privada. Retornan la firma codificada en hex

* `verify_signature`, `verify_signature_file`

Reciben un mensaje o la ruta a un archivo respectivamente, firma y la llave pública. Retorna un bool indicando si la firma coincide con la llave y el mensaje
