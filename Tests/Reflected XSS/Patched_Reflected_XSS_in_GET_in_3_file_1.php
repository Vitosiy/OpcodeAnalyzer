<?php

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

function patched_danger_function($arg)
{
    $tmp = $arg . "!!! \n"; 
    echo htmlspecialchars($tmp);
}

?>

