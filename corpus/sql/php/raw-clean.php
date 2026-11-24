<?php
// The same endpoint, with a bound parameter.
$id = $_GET['id'];
$db = new PDO('mysql:host=localhost;dbname=shop', 'shop', 'secret');
$stmt = $db->prepare('SELECT id, name FROM users WHERE id = ?');
$stmt->execute([$id]);
foreach ($stmt as $row) {
    echo htmlspecialchars($row['name']);
}
