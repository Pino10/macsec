<?php
// A search page that puts the request straight into a query.
$name = $_GET['name'];
$db = new PDO('mysql:host=localhost;dbname=shop', 'shop', 'secret');
$sql = "SELECT id, name FROM users WHERE name = '" . $name . "'";
$rows = $db->query($sql);
foreach ($rows as $row) {
    echo htmlspecialchars($row['name']);
}
