<?php
    $db = new mysqli("localhost", "root", "root", "productsdb");
    /*if ($db == false){
        echo "Ошибка: Невозможно подключиться к MySQL " . mysqli_connect_error();
    }
    else {
        echo "Соединение установлено успешно";
    }*/
	
    $result = $db->query("SELECT * FROM Products;");
    if($result)
    {
        echo "<h2>Таблица Products: </h2>";
        echo "<table border='1'>";
		while ($row = mysqli_fetch_assoc($result)) { // Check summary get row on array
			echo "<tr>";
			foreach ($row as $field => $value) { // I you want you can right this line like this: foreach($row as $value) {
				echo "<td>" . $value . "</td>"; // I just did not use "htmlspecialchars()" function. 
			}
			echo "</tr>";
		}
		echo "</table>";
    }
    else 
    {
       
	   echo($db->error);
    } 

?>
