<?php

function unsecure_function()
{
    return $_GET['var'];
}

function danger_function($arg)
{
    echo $arg;
}

?>

