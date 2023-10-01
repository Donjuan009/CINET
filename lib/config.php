<?php
define('HOST', 'localhost');
define('DB', 'id21335481_cinet');
define('USER', 'id21335481_donjuan');
define('PASSWORD', 'Juanes99#');

$link = mysqli_connect(HOST, USER, PASSWORD, DB);
mysqli_set_charset($link, 'utf8');

if($link == false){
    die('ERROR: NO SE CONECTO A LA BASE DE DATOS.'. mysqli_connect_error());
}



?>