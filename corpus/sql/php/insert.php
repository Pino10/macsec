<?php
// A newsletter signup writes the request straight into the insert.
$email = $_POST['email'];
$db = new PDO('mysql:host=localhost;dbname=shop', 'shop', 'secret');
$db->exec("INSERT INTO subscribers (email) VALUES ('" . $email . "')"); // MACSEC-SQLI
