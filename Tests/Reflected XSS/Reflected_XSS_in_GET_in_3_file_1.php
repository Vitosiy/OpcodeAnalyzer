<?php

function unsecure_function()
{
    $get = $_GET['var'];
    if(isset($get)) {
    	return $get;
    } else {
    	return 0;
    }
}

function danger_function($arg)
{
    $tmp = $arg . "!!! \n"; 
    echo $tmp;
}

?>

