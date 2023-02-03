<?php

include 'Reflected_XSS_in_GET_in_2_file_1.php';

$get_var = unsecure_function();
danger_function($get_var);

?>

