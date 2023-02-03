<?php

function unsecure_function()
{
    $get = $_GET['var'];
    if(isset($get)) {
    	return $get;
    }
    else {
    	return 0;
    }
}
function danger_function($arg)
{
    $tmp = $arg . "!!! \n"; 
    echo $tmp;
}

#Patch 1
function patched_unsecure_function()
{
    $get = htmlspecialchars($_GET['var']);
    if(isset($get)) {
    	return $get;
    }
    else {
    	return 0;
    }
}
$get_var = patched_unsecure_function();
danger_function($get_var);

#Patch 2
function patched_danger_function($arg)
{
    $tmp = $arg . "!!! \n"; 
    echo htmlspecialchars($tmp);
}
$get_var = unsecure_function();
patched_danger_function($get_var);

#Patch 3 (bad)
$get_var = patched_unsecure_function();
patched_danger_function($get_var);


?>

