Login come root

```
mkdir /var/www/_newsrl
cd /var/www/_newsrl
wget -O cdr.php https://raw.githubusercontent.com/canvacanva/NEW-SRL-cdr/main/cdr.php
nano cdr.php
```

Modificare utente e pass con quelli per accedere al db:
```
const DB_HOST = 'localhost';
const DB_NAME = 'cdr';
const DB_USER = 'root';
const DB_PASS = 'PASSWORD_DB_WILDIX';
```
