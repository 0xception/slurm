<?php
    $ref = $_GET['ref'];

    if ($ref == "example.png") {
        $file = "../images/example.png";
        if (file_exists($file)) {
            header("Content-Type: image/png");
            readfile($file);
            exit;
        }
    }
?>
