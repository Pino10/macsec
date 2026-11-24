<?php
// The same signup, with a bound value.
$email = $_POST['email'];
$db = new PDO('mysql:host=localhost;dbname=shop', 'shop', 'secret');
$stmt = $db->prepare('INSERT INTO subscribers (email) VALUES (?)');
$stmt->execute([$email]);
