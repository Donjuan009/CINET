<?php
require_once "lib/config.php";
$nombre = $correo = $password = $confirm_password = $telefono = $tdocumento = $documento = "";
$nombre_err = $password_err = $confirm_password_err = $telefono_err = $correo_err = $documento_err = "";
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    if (empty(trim($_POST["correo"]))) {
        $correo_err = "Por favor ingresa un correo electronico.";
    } elseif (!filter_var(trim($_POST["correo"]), FILTER_VALIDATE_EMAIL)) {
        $correo_err = "El correo electronico es incorrecto.";
    } else {
        $sql = "SELECT id FROM usuarios WHERE correo = ?";
        if ($stmt = mysqli_prepare($link, $sql)) {
            mysqli_stmt_bind_param($stmt, "s", $param_username);
            $param_username = trim($_POST["correo"]);
            if (mysqli_stmt_execute($stmt)) {
                mysqli_stmt_store_result($stmt);
                if (mysqli_stmt_num_rows($stmt) == 1) {
                    $correo_err = "El correo ya esta siendo utilizado.";
                } else {
                    $correo = trim($_POST["correo"]);
                }
            } else {
                echo "¡Ups! Algo salió mal. Por favor, inténtelo de nuevo más tarde.";
            }

            mysqli_stmt_close($stmt);
        }
    }


    if (empty(trim($_POST["nombre"]))) {
        $nombre_err = "Ingresa tu nombre.";
    } elseif (strlen(trim($_POST["nombre"])) < 6) {
        $nombre_err = "Ingresa tu nombre completo.";
    } else {
        $nombre = trim($_POST["nombre"]);
    }
    if (empty(trim($_POST["documento"]))) {
        $documento_err = "Ingresa tu numero de documento.";
    } elseif (strlen(trim($_POST["documento"])) < 5) {
        $documento_err = "Ingresa un numero de documento completo";
    } else {
        $documento = trim($_POST["documento"]);
    }

    if (empty(trim($_POST["telefono"]))) {
        $telefono_err = "Ingresa tu numero de telefono.";
    } elseif (strlen(trim($_POST["telefono"])) != 10) {
        $telefono_err = "Ingresa un numero de telefono valido";
    } else {
        $telefono = trim($_POST["telefono"]);
    }


    if (empty(trim($_POST["password"]))) {
        $password_err = "Por favor ingresa una contraseña.";
    } elseif (strlen(trim($_POST["password"])) < 6) {
        $password_err = "Tu contraseña es insegura agrega mas caracteres.";
    } else {
        $password = trim($_POST["password"]);
    }   
    if (empty(trim($_POST["confirm_password"]))) {
        $confirm_password_err = "Por favor confirma tu contraseña.";
    } else {
        $confirm_password = trim($_POST["confirm_password"]);
        if (empty($password_err) && ($password != $confirm_password)) {
            $confirm_password_err = "La contraseña no coincide.";
        }
    }

    $tdocumento = $_POST['tdocumento'];

    if (empty($correo_err) && empty($password_err) && empty($confirm_password_err)) {
        $sql = "INSERT INTO usuarios (nombre, correo, password, telefono, tdocumento, documento) VALUES (?, ?, ?, ?, ?, ?)";
    if ($stmt = mysqli_prepare($link, $sql)) {
        mysqli_stmt_bind_param($stmt, "ssssss", $param_nombre, $param_correo, $param_password, $param_telefono, $param_tdocumento, $param_documento);

        $param_nombre = $nombre;
        $param_correo = $correo;
        $param_password = password_hash($password, PASSWORD_DEFAULT);
        $param_telefono = $telefono;
        $param_tdocumento = $tdocumento;
        $param_documento = $documento;

        if (mysqli_stmt_execute($stmt)) {
            header("location: login.php");
            exit(); // Importante: asegúrate de salir del script después de redirigir.
        } else {
            echo "Oops! Something went wrong. Please try again later.";
        }
        mysqli_stmt_close($stmt);
    }
    mysqli_close($link);
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Registro CINET</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@4.5.2/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
    <div class="container mt-5">
        <div class="row justify-content-center">
            <div class="col-md-6">
                <div class="card">
                    <div class="card-header">
                        Registro de Usuario
                    </div>
                    <div class="card-body">
                        <form action="<?php echo htmlspecialchars($_SERVER["PHP_SELF"]); ?>" method="post">
                            <div class="form-group">
                                <label for="nombre">Nombre</label>
                                <input type="text" class="form-control" id="nombre" name="nombre" value="<?php echo $nombre; ?>" placeholder="Ingrese su nombre">
                                <span id="nombreError" class="text-danger"><?php echo $nombre_err; ?></span>
                            </div>
                            <div class="form-group">
                                <label for="correo">Correo Electrónico</label>
                                <input type="email" class="form-control" id="correo" value="<?php echo $correo; ?>" name="correo" placeholder="Ingrese su correo electrónico">
                                <span id="correoError" class="text-danger"><?php echo $correo_err; ?></span>
                            </div>
                            <div class="form-group">
                                <label for="contrasena">Contraseña</label>
                                <input type="password" class="form-control" id="contrasena" name="password" placeholder="Ingrese su contraseña">
                                <span id="contrasenaError" class="text-danger"><?php echo $password_err; ?></span>
                            </div>
                            <div class="form-group">
                                <label for="contrasena">Confirma tu contraseña</label>
                                <input type="password" class="form-control" id="contrasena" name="confirm_password" placeholder="Ingrese su contraseña">
                                <span id="contrasenaError" class="text-danger"><?php echo $confirm_password_err; ?></span>
                            </div>
                            <div class="form-group">
                                <label for="telefono">Teléfono</label>
                                <input type="tel" class="form-control" name="telefono" id="telefono" value="<?php echo $telefono; ?>" placeholder="Ingrese su número de teléfono">
                                <span id="telefonoError" class="text-danger"><?php echo $telefono_err; ?></span>
                            </div>
                            <div class="form-group">
                                <label for="tdocumento">Tipo de Documento</label>
                                <select class="form-control" name="tdocumento" id="tdocumento">
                                    <option value="cedula">Cédula</option>
                                    <option value="dni">DNI</option>
                                    <option value="pasaporte">Pasaporte</option>
                                    
                                </select>
                            </div>
                            <div class="form-group">
                                <label for="documento">Número de Documento</label>
                                <input type="tel" class="form-control" name="documento" id="documento" value="<?php echo $documento; ?>" placeholder="Ingrese su número de documento">
                                <span id="documentoError" class="text-danger"><?php echo $documento_err; ?></span>
                            </div>
                            <button type="submit" class="btn btn-primary">Registrarse</button>
                        </form>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- Incluye los archivos JavaScript de Bootstrap (jQuery y Popper.js son necesarios) -->
    <script src="https://code.jquery.com/jquery-3.5.1.slim.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/popper.js@1.16.0/dist/umd/popper.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@4.5.2/dist/js/bootstrap.min.js"></script>
</body>
</html>
