<?php
// Test target file with intentional vulnerabilities for PoC verification

// SQL Injection
$id = $_GET['id'];
$query = "SELECT * FROM users WHERE user_id = '$id'";
$result = mysqli_query($conn, $query);

// Command Injection
$ip = $_GET['ip'];
$output = shell_exec("ping -c 4 " . $ip);

// XSS Reflected
$name = $_GET['name'];
echo "<pre>Hello " . $name . "</pre>";

// File Inclusion
$page = $_GET['page'];
include($page);

// File Upload
$target_path = "uploads/" . basename($_FILES['uploaded']['name']);
move_uploaded_file($_FILES['uploaded']['tmp_name'], $target_path);

// CSRF - no token check
$new_pass = $_POST['password_new'];
$conf_pass = $_POST['password_conf'];
if ($new_pass == $conf_pass) {
    mysqli_query($conn, "UPDATE users SET password = '$new_pass'");
}

// Open Redirect
$url = $_GET['url'];
header("Location: " . $url);

// Weak Session
session_start();
$_SESSION['id'] = $_GET['id'] + 1;

// Auth Bypass - type juggling
if ($_POST['password'] == $stored_hash) {
    echo "Welcome admin";
}

// Dynamic Code Execution
$cmd = $_GET['cmd'];
eval($cmd);

// Cryptography - weak cipher
$text = $_GET['text'];
$shift = $_GET['shift'];
for ($i = 0; $i < strlen($text); $i++) {
    $text[$i] = chr(ord($text[$i]) + $shift);
}
?>
