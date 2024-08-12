//------------------ append to previous data in functions.php---------------------
include "php-jwt.php";

define('JWT_SECRET_KEY', 'TEST');
define('RATE_LIMIT', 10); // 100 requests per hour
define('TIME_FRAME', 30); // Time frame in seconds (1 hour)
define('PRE_SHARED_KEY', 'adl'); // Change to your pre-shared key

function rate_limit_check() {
    $ip = $_SERVER['REMOTE_ADDR'];
    $request_count = get_transient("rate_limit_{$ip}_count");
    $first_request_time = get_transient("rate_limit_{$ip}_time");

    if ($request_count === false) {
        set_transient("rate_limit_{$ip}_count", 1, TIME_FRAME);
        set_transient("rate_limit_{$ip}_time", time(), TIME_FRAME);
    } else {
        if ($request_count >= RATE_LIMIT) {
            // Too many requests
            $wait_time = TIME_FRAME - (time() - $first_request_time);
            return new WP_Error('rate_limit_exceeded', 'Rate limit exceeded. Try again in ' . gmdate("i:s", $wait_time) . ' minutes.', array('status' => 429));
        } else {
            // Increment the request count
            set_transient("rate_limit_{$ip}_count", $request_count + 1, TIME_FRAME);
        }
    }

    return true;
}

// Logging Function
function log_api_request($endpoint) {
    $ip = $_SERVER['REMOTE_ADDR'];
    $user_agent = $_SERVER['HTTP_USER_AGENT'];
    $timestamp = date("Y-m-d H:i:s");
    $log_entry = "{$timestamp} - {$ip} accessed {$endpoint} using {$user_agent}\n";

    // Save the log entry to a file or database
    file_put_contents(__DIR__ . '/api_requests.log', $log_entry, FILE_APPEND);
}


function check_preshared_key() {
    $provided_key = isset($_SERVER['HTTP_X_PRESHARED_KEY']) ? $_SERVER['HTTP_X_PRESHARED_KEY'] : '';

    if ($provided_key !== PRE_SHARED_KEY) {
        return new WP_Error('unauthorized_access', 'Unauthorized access. Invalid pre-shared key.', array('status' => 403));
    }

    return true;
}

// Generate JWT Token
function generate_jwt_token($user_id) {
    $issuedAt = time();
    $expirationTime = $issuedAt + (60 * 60);  // jwt valid for 1 hour
    $payload = array(
        'iat' => $issuedAt,
        'exp' => $expirationTime,
        'data' => array(
            'user_id' => $user_id
        )
    );

    return JWT::encode($payload, JWT_SECRET_KEY);
}

function validate_jwt_token($token) {
    try {
        $decoded = JWT::decode($token, JWT_SECRET_KEY);
        return $decoded['data']['user_id'];
    } catch (Exception $e) {
        return null;
    }
}

// Register REST API Endpoints
add_action('rest_api_init', function () {
    register_rest_route('custom/v1', '/login', array(
        'methods' => 'POST',
        'callback' => 'custom_login',
    ));

    register_rest_route('custom/v1', '/register', array(
        'methods' => 'POST',
        'callback' => 'custom_register',
    ));
});

// Login Callback
function custom_login($request) {
    // Rate Limit Check
    $rate_limit_check = rate_limit_check();
    if (is_wp_error($rate_limit_check)) {
        return $rate_limit_check;
    }

    // Log the request
    log_api_request('/login');

    // Pre-shared Key Check
    $preshared_key_check = check_preshared_key();
    if (is_wp_error($preshared_key_check)) {
        return $preshared_key_check;
    }

    $username = sanitize_text_field($request['username']);
    $password = sanitize_text_field($request['password']);

    $user = wp_authenticate($username, $password);

    if (is_wp_error($user)) {
        return new WP_Error('invalid_credentials', 'Invalid username or password', array('status' => 403));
    }

    $token = generate_jwt_token($user->ID);

    return array(
        'token' => $token,
        'user_id' => $user->ID,
        'username' => $user->user_login,
        'email' => $user->user_email
    );
}

// Register Callback
function custom_register($request) {
    // Rate Limit Check
    $rate_limit_check = rate_limit_check();
    if (is_wp_error($rate_limit_check)) {
        return $rate_limit_check;
    }

    // Log the request
    log_api_request('/register');

    // Pre-shared Key Check
    $preshared_key_check = check_preshared_key();
    if (is_wp_error($preshared_key_check)) {
        return $preshared_key_check;
    }

    $username = sanitize_text_field($request['username']);
    $password = sanitize_text_field($request['password']);
    $email = sanitize_email($request['email']);

    if (username_exists($username) || email_exists($email)) {
        return new WP_Error('user_exists', 'Username or Email already exists', array('status' => 400));
    }

    $user_id = wp_create_user($username, $password, $email);

    if (is_wp_error($user_id)) {
        return new WP_Error('registration_failed', 'User registration failed', array('status' => 500));
    }

    // Optionally, send a welcome email to the user
    wp_new_user_notification($user_id, null, 'user');

    return array(
        'user_id' => $user_id,
        'username' => $username,
        'email' => $email,
    );
}
//-----------------------------jwt-----------------------

function handle_token_login() {
  
      $user_ip = $_SERVER['REMOTE_ADDR'];


    if (check_rate_limit($user_ip)) {
        wp_die('Rate limit exceeded. Please try again later.', 'Too Many Requests', array('response' => 429));
    }
  
  
  
    if (isset($_GET['token'])) {
        $token = $_GET['token'];

        // Validate the token and get the user ID
        $user_id = validate_jwt_token($token);

        if ($user_id) {
            // Log the user in
            wp_set_auth_cookie($user_id);

            // Redirect to the home page or a custom page after successful login
            wp_safe_redirect(home_url());
            exit;
        } else {
            // Handle invalid token by showing an error message or redirecting
            wp_die('Invalid token. You are not authorized to view this page.', 'Unauthorized', array('response' => 403));
        }
    }
}
add_action('template_redirect', 'handle_token_login');

//-----------------------------------user_exists_endpoint------------------------------------------

function check_user_exists( WP_REST_Request $request ) {
    $username = $request->get_param('username');
    
    if ( empty( $username ) ) {
        return new WP_REST_Response( 
            array( 'exists' => false, 'message' => 'Username parameter is required.' ), 
            400 
        );
    }

    $user = get_user_by( 'login', $username );

    if ( $user ) {
        return new WP_REST_Response( 
            array( 'exists' => true, 'message' => 'User exists.' ), 
            200 
        );
    } else {
        return new WP_REST_Response( 
            array( 'exists' => false, 'message' => 'User does not exist.' ), 
            404 
        );
    }
}

function register_user_exists_route() {
    register_rest_route( 'custom/v1', '/user-exists/', array(
        'methods' => 'GET',
        'callback' => 'check_user_exists',
    ));
}

add_action( 'rest_api_init', 'register_user_exists_route' );

