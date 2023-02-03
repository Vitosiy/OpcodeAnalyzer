<?php

function patched_unsecure_function()
{
    return htmlspecialchars($_GET['var']);
}

function patched_danger_function($arg)
{
    echo htmlspecialchars($arg);
}

?>

