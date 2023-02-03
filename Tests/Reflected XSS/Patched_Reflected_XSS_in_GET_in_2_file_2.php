<?php

include 'Reflected_XSS_in_GET_in_2_file_1.php';
include 'Patched_Reflected_XSS_in_GET_in_2_file_1.php';

#Patch 1
$get_var = htmlspecialchars(unsecure_function());
danger_function($get_var);

#Patch 2
$get_var = unsecure_function();
danger_function(htmlspecialchars($get_var));

#Patch 3 (bad)
$get_var = htmlspecialchars(unsecure_function());
danger_function(htmlspecialchars($get_var));

#Patch 4
$get_var = patched_unsecure_function();
danger_function($get_var);

#Patch 5
$get_var = unsecure_function();
patched_danger_function($get_var);

#Patch 6 (bad)
$get_var = patched_unsecure_function();
patched_danger_function($get_var);

#Patch 7 (bad)
$get_var = htmlspecialchars(patched_unsecure_function());
patched_danger_function(htmlspecialchars($get_var));

?>

