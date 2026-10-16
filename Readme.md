Login come root

Creare file credenziali
```
mkdir /var/credentials
cd /var/credentials
```

Creare una hash per la password web, annotarlo
```
php -r "echo password_hash('LA_PASSWORD', PASSWORD_DEFAULT), PHP_EOL;"
```

creare il file di credenziali
```
nano /var/credentials/cdr_export.php
```

copiare il contenuto su cdr_export.php ed scegiere user e pass hash
```
<?php
$cdrweb_user = 'report';
$cdrweb_hash = '...';
```
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
