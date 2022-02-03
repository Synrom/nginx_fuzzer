# NGINX-Fuzzer

nginx umgeschrieben, so dass eine Request in der Datei, die mit -S uebergeben wird, bearbeitet wird.
Alles das, was eigentlich gesendet werden wuerde wird nach Stdout geschrieben.

## Beispiel

./objs/nginx -p . -S sample
