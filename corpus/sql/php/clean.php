<?php
// The same search, with a prepared statement.
$name = $_GET['name'];
$db = new PDO('mysql:host=localhost;dbname=shop', 'shop', 'secret');
$stmt = $db->prepare('SELECT id, name FROM users WHERE name = ?');
$stmt->execute([$name]);
foreach ($stmt as $row) {
    echo htmlspecialchars($row['name']);
}
