<?php
session_start();
define('URLPREFIX', 'https://Admin-yar.com/wp-json/custom/v1');
define('WP_SITE', 'Admin-yar.com/');
define('UPLOAD_FOLDER', 'uploads/');

function generate_sms_token() {
    return rand(10000, 99999);
}

function wp_register($username, $password, $email) {
    $url = URLPREFIX . "/register";
    $payload = json_encode([
        "username" => $username,
        "password" => $password,
        "email" => $email
    ]);

    $options = [
        'http' => [
            'header' => "Content-Type: application/json\r\n" .
                        "X-PRESHARED-KEY: adl\r\n",
            'method' => 'POST',
            'content' => $payload,
        ],
    ];

    $context = stream_context_create($options);
    $result = file_get_contents($url, false, $context);

    if ($result === FALSE) {
        return null;
    }

    return json_decode($result, true);
}

function wp_login($username, $password) {
    $url = URLPREFIX . "/login";
    $payload = json_encode([
        "username" => $username,
        "password" => $password,
    ]);

    $options = [
        'http' => [
            'header' => "Content-Type: application/json\r\n" .
                        "X-PRESHARED-KEY: adl\r\n",
            'method' => 'POST',
            'content' => $payload,
        ],
    ];

    $context = stream_context_create($options);
    $result = file_get_contents($url, false, $context);

    if ($result === FALSE || $http_response_header[0] != "HTTP/1.1 200 OK") {
        return null;
    }

    return json_decode($result, true);
}

function hash_password($password) {
    return hash('sha256', $password);
}

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    $action = $_POST['action'];

    switch ($action) {
        case 'register':
            $username = $_POST['username'];
            $password = $_POST['password'];
            if (!$username || !$password) {
                echo json_encode(["error" => "Username and password are required"]);
                http_response_code(400);
                exit();
            }

            $resp = wp_register($username, $password, "{$username}@a.com");
            if ($resp === null) {
                echo json_encode(["error" => "Unknown error"]);
                http_response_code(500);
            } else {
                echo json_encode($resp);
                http_response_code(200);
            }
            break;

        case 'login':
            $username = $_POST['username'];
            $password = $_POST['password'];
            if (!$username || !$password) {
                echo json_encode(["error" => "Username and password are required"]);
                http_response_code(400);
                exit();
            }

            $hashed_password = hash_password($password);
            $response_from_wp = wp_login($username, $password);
            if ($response_from_wp === null) {
                error_log("[" . date('Y-m-d H:i:s') . "] Wrong credential login for $username\n", 3, 'errors.log');
                echo json_encode(["error" => "Invalid credentials"]);
                http_response_code(401);
            } else {
                $token = $response_from_wp['token'];
                error_log("[" . date('Y-m-d H:i:s') . "] Successful login for $username\n", 3, 'logins.log');
                echo json_encode(["message" => "Login successful", "redirect_url" => "https://" . WP_SITE . "/?token=$token"]);
            }
            break;

        case 'send_sms_code':
            $num = $_POST['phone_number'];
            if (!$num) {
                echo json_encode(["message" => "Error! number does not exist in parameters"]);
                http_response_code(500);
                exit();
            }

            $exists = file_get_contents("https://admin-yar.com/wp-json/custom/v1/user-exists/?username=$num");
            if ($exists === "200") {
                echo json_encode(["message" => "user already Exists!"]);
                http_response_code(201);
            } else {
                $sms_code = generate_sms_token();
                $_SESSION['NUMBERS_token'][$num] = $sms_code;
                // Replace with your SMS API call
                echo json_encode(['message' => 'کد پیامک ارسال شد']);
                http_response_code(200);
            }
            break;

        case 'verify_sms_code':
            $sms_code = $_POST['sms_code'];
            $num = $_POST['number'];
            if ($_SESSION['NUMBERS_token'][$num] == $sms_code) {
                $resp = wp_register($num, $num, "$num@admin-yar.com");
                if ($resp !== null) {
                    echo json_encode(['message' => 'کد تایید شد', 'user_id' => $resp["user_id"]]);
                } else {
                    echo json_encode(['message' => 'خطا هنگام ثبت نام']);
                    http_response_code(400);
                }
            } else {
                echo json_encode("error");
                http_response_code(400);
            }
            break;

        case 'upload_resume':
            if (isset($_FILES['file']) && $_FILES['file']['type'] == 'application/pdf' && $_FILES['file']['size'] <= 2097152) {
                $user_id = $_POST['user_id'];
                $filename = UPLOAD_FOLDER . $user_id . ".pdf";
                move_uploaded_file($_FILES['file']['tmp_name'], $filename);
                echo json_encode(['message' => 'رزومه با موفقیت آپلود شد']);
            } else {
                echo json_encode(['message' => 'مشکلی در آپلود فایل وجود دارد']);
                http_response_code(400);
            }
            break;

        case 'delete_resume':
            $user_id = $_POST['user'];
            $filename = UPLOAD_FOLDER . $user_id . ".pdf";
            if (file_exists($filename)) {
                unlink($filename);
                echo json_encode(['message' => 'رزومه با موفقیت حذف شد']);
            } else {
                echo json_encode(['message' => 'فایل پیدا نشد']);
                http_response_code(400);
            }
            break;

        default:
            echo json_encode(['message' => 'Invalid action']);
            http_response_code(400);
            break;
    }
} else {
    // Load the index page (HTML form)
    include 'index.html';
}
?>
