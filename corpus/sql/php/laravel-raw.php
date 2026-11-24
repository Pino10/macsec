<?php
// A report page that builds the query with DB::select.
$name = request('name');
$rows = DB::select("SELECT id, name FROM users WHERE name = '" . $name . "'"); // MACSEC-SQLI
foreach ($rows as $row) {
    echo e($row->name);
}
