<?php

function unsecure_function()
{
    $get = $_GET['var'];
    if(isset($get)) {
    	return $get;
    } else {
    	return "Error";
    }
}

function danger_function($arg)
{
    $tmp = $arg . "!!! \n"; 
    echo $tmp;
}

$get_var = unsecure_function();
danger_function($get_var);

?>

