<?php
    $db = new mysqli("localhost", "root", "root", "productsdb");
    /*if ($db == false){
        echo "Ошибка: Невозможно подключиться к MySQL " . mysqli_connect_error();
    }
    else {
        echo "Соединение установлено успешно";
    }*/
    $var = $_GET['var'];
    $result = $db->query("SELECT * FROM Products WHERE Id = \"$var\";");
    if($result)
    {
        echo "<h2>Таблица Products: </h2>";
        echo "<table border='1'>";
		while ($row = mysqli_fetch_assoc($result)) { 
			foreach ($row as $field => $value) { 
				echo "<td>" . $value . "</td>";
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
