<?php

#Patch 1
function patched_unsecure_function()
{
    return htmlspecialchars($_GET['var']);
}
function danger_function($arg)
{
    echo $arg . "\n";
}
$get_var = patched_unsecure_function();
danger_function($get_var);

#Patch 2
function unsecure_function()
{
    return $_GET['var'];
}
function patched_danger_function($arg)
{
    echo htmlspecialchars($arg) . "\n";
}
$get_var = unsecure_function();
patched_danger_function($get_var);

#Patch 3
$get_var = htmlspecialchars(unsecure_function());
danger_function($get_var);

#Patch 4
$get_var = unsecure_function();
danger_function(htmlspecialchars($get_var));

#Patch 5
$get_var = unsecure_function();
$get_var = htmlspecialchars($get_var);
danger_function($get_var);

#Patch 6 (bad)
$get_var = patched_unsecure_function();
patched_danger_function($get_var);

?>

