# NGINX-Fuzzer

nginx umgeschrieben, so dass eine Request in der Datei, die mit -S uebergeben wird, bearbeitet wird.
Alles, das eigentlich gesendet werden wuerde wird nach Stdout geprintet.

## Beispiel

./obj/nginx -p . -S sample
