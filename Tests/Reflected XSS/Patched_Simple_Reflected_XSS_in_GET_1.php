<?php

#Patch 1
if (isset($_GET['var'])) {
    $get_var = $_GET['var'];
    $get_var = htmlspecialchars($get_var);
    echo $get_var;
}

#Patch 2
if (isset($_GET['var'])) {
    $get_var = htmlspecialchars($_GET['var']);
    echo $get_var;
}

#Patch 3
if (isset($_GET['var'])) {
    $get_var = $_GET['var'];
    echo htmlspecialchars($get_var);
}

#Patch 4
if (isset($_GET['var'])) {
    echo htmlspecialchars($_GET['var']);
}

?>

