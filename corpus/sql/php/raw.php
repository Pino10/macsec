<?php
// A small API endpoint with a hand-built SQL string.
$id = $_GET['id'];
$db = new PDO('mysql:host=localhost;dbname=shop', 'shop', 'secret');
$rows = $db->query('SELECT id, name FROM users WHERE id = ' . $id); // MACSEC-SQLI
foreach ($rows as $row) {
    echo htmlspecialchars($row['name']);
}
