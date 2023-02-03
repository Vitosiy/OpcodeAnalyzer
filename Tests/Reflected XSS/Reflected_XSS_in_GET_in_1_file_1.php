<?php

function unsecure_function()
{
    return $_GET['var'];
}

function danger_function($arg)
{
    echo $arg . "\n";
}

$get_var = unsecure_function();
danger_function($get_var);

?>

