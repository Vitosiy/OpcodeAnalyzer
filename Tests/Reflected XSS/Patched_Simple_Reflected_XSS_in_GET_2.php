<?php

#Patch 1
$get = htmlspecialchars($_GET['var']);
if (isset($get)) {
    $get_var = $get;
    echo $get_var;
}

#Patch 2
$get = $_GET['var'];
if (isset($get)) {
    $get_var = htmlspecialchars($get);
    echo $get_var;
}

#Patch 3
$get = $_GET['var'];
if (isset($get)) {
    $get_var = $get;
    echo htmlspecialchars($get_var);
}


?>

