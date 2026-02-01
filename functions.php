<?php

// آرایه جهانی برای ذخیره امضای کانفیگ‌ها جهت جلوگیری از تکرار
$seen_signatures = [];

/** Detect Type of Config */
function detect_type($input)
{
    $type = "";
    if (substr($input, 0, 8) === "vmess://") {
        $type = "vmess";
    } elseif (substr($input, 0, 8) === "vless://") {
        $type = "vless";
    } elseif (substr($input, 0, 9) === "trojan://") {
        $type = "trojan";
    } elseif (substr($input, 0, 5) === "ss://") {
        $type = "ss";
    }

    return $type;
}

function parse_config($input)
{
    $type = detect_type($input);
    $parsed_config = [];
    switch ($type) {
        case "vmess":
            $parsed_config = decode_vmess($input);
            break;
        case "vless":
        case "trojan":
            $parsed_config = parseProxyUrl($input, $type);
            break;
        case "ss":
            $parsed_config = ParseShadowsocks($input);
            break;
    }
    return $parsed_config;
}

function build_config($input, $type)
{
    $build_config = "";
    switch ($type) {
        case "vmess":
            $build_config = encode_vmess($input);
            break;
        case "vless":
        case "trojan":
            $build_config = buildProxyUrl($input, $type);
            break;
        case "ss":
            $build_config = BuildShadowsocks($input);
            break;
    }
    return $build_config;
}

/** parse vmess configs */
function decode_vmess($vmess_config)
{
    $vmess_data = substr($vmess_config, 8); // remove "vmess://"
    $decoded_data = json_decode(base64_decode($vmess_data), true);
    return $decoded_data;
}

/** build vmess configs */
function encode_vmess($config)
{
    $encoded_data = base64_encode(json_encode($config));
    $vmess_config = "vmess://" . $encoded_data;
    return $vmess_config;
}

/** Parse vless and trojan config*/
function parseProxyUrl($url, $type = "trojan")
{
    $parsedUrl = parse_url($url);
    $params = [];
    if (isset($parsedUrl["query"])) {
        parse_str($parsedUrl["query"], $params);
    }

    $output = [
        "protocol" => $type,
        "username" => isset($parsedUrl["user"]) ? $parsedUrl["user"] : "",
        "hostname" => isset($parsedUrl["host"]) ? $parsedUrl["host"] : "",
        "port" => isset($parsedUrl["port"]) ? $parsedUrl["port"] : "",
        "params" => $params,
        "hash" => isset($parsedUrl["fragment"]) ? $parsedUrl["fragment"] : "",
    ];

    return $output;
}

/** Build vless and trojan config*/
function buildProxyUrl($obj, $type = "trojan")
{
    $url = $type . "://";
    $url .= addUsernameAndPassword($obj);
    $url .= $obj["hostname"];
    $url .= addPort($obj);
    $url .= addParams($obj);
    $url .= addHash($obj);
    return $url;
}

function addUsernameAndPassword($obj)
{
    $url = "";
    if ($obj["username"] !== "") {
        $url .= $obj["username"];
        if (isset($obj["pass"]) && $obj["pass"] !== "") {
            $url .= ":" . $obj["pass"];
        }
        $url .= "@";
    }
    return $url;
}

function addPort($obj)
{
    $url = "";
    if (isset($obj["port"]) && $obj["port"] !== "") {
        $url .= ":" . $obj["port"];
    }
    return $url;
}

function addParams($obj)
{
    $url = "";
    if (!empty($obj["params"])) {
        $url .= "?" . http_build_query($obj["params"]);
    }
    return $url;
}

function addHash($obj)
{
    $url = "";
    if (isset($obj["hash"]) && $obj["hash"] !== "") {
        $url .= "#" . $obj["hash"];
    }
    return $url;
}

/** parse shadowsocks configs */
function ParseShadowsocks($config_str)
{
    $url = parse_url($config_str);
    list($encryption_method, $password) = explode(
        ":",
        base64_decode($url["user"])
    );
    $server_address = $url["host"];
    $server_port = $url["port"];
    $name = isset($url["fragment"]) ? urldecode($url["fragment"]) : null;

    $server = [
        "encryption_method" => $encryption_method,
        "password" => $password,
        "server_address" => $server_address,
        "server_port" => $server_port,
        "name" => $name,
    ];

    return $server;
}

/** build shadowsocks configs */
function BuildShadowsocks($server)
{
    $user = base64_encode(
        $server["encryption_method"] . ":" . $server["password"]
    );
    $url = "ss://$user@{$server["server_address"]}:{$server["server_port"]}";
    if (!empty($server["name"])) {
        $url .= "#" . urlencode($server["name"]);
    }
    return $url;
}

function is_ip($string)
{
    $ipv4_pattern = '/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/';
    $ipv6_pattern = '/^[0-9a-fA-F:]+$/';

    if (preg_match($ipv4_pattern, $string) || preg_match($ipv6_pattern, $string)) {
        return true;
    } else {
        return false;
    }
}

function ip_info($ip)
{
    if (is_ip($ip) === false) {
        $ip_address_array = dns_get_record($ip, DNS_A);
        if (is_array($ip_address_array) && !empty($ip_address_array)) {
            $randomKey = array_rand($ip_address_array);
            $ip = $ip_address_array[$randomKey]["ip"];
        }
    }

    // استفاده از API سایت iplocation.net (iplocation.io)
    $url = "https://api.iplocation.net/?ip=" . $ip;

    $response = @file_get_contents($url);
    if ($response === false) {
        return null;
    }
    $ipinfo = json_decode($response, true);
    return $ipinfo;
}

function get_flag($ip)
{
    $flag = "";
    $ip_info = ip_info($ip);
    // در iplocation.net کد کشور با کلید country_code2 برگردانده می‌شود
    if ($ip_info && isset($ip_info["country_code2"])) {
        $location = $ip_info["country_code2"];
        $flag = $location . " " . getFlags($location);
    } else {
        $flag = "RELAY 🚩";
    }
    return $flag;
}

function getFlags($country_code)
{
    $country_code = strtoupper($country_code);
    $flag = mb_convert_encoding(
        "&#" . (127397 + ord($country_code[0])) . ";",
        "UTF-8",
        "HTML-ENTITIES"
    );
    $flag .= mb_convert_encoding(
        "&#" . (127397 + ord($country_code[1])) . ";",
        "UTF-8",
        "HTML-ENTITIES"
    );
    return $flag;
}

function get_ip($config, $type, $is_reality)
{
    switch ($type) {
        case "vmess":
            return get_vmess_ip($config);
        case "vless":
            return get_vless_ip($config, $is_reality);
        case "trojan":
            return get_trojan_ip($config);
        case "ss":
            return get_ss_ip($config);
    }
}

function get_vmess_ip($input)
{
    return !empty($input["sni"])
        ? $input["sni"]
        : (!empty($input["host"])
            ? $input["host"]
            : $input["add"]);
}

function get_vless_ip($input, $is_reality)
{
    return $is_reality
        ? $input["hostname"]
        : (!empty($input["params"]["sni"])
            ? $input["params"]["sni"]
            : (!empty($input["params"]["host"])
                ? $input["params"]["host"]

                : $input["hostname"]));
}

function get_trojan_ip($input)
{
    return !empty($input["params"]["sni"])
        ? $input["params"]["sni"]
        : (!empty($input["params"]["host"])
            ? $input["params"]["host"]
            : $input["hostname"]);
}

function get_ss_ip($input)
{
    return $input["server_address"];
}

function get_port($input, $type)
{
    $port = "";
    switch ($type) {
        case "vmess":
            $port = $input["port"];
            break;
        case "vless":
            $port = $input["port"];
            break;
        case "trojan":
            $port = $input["port"];
            break;
        case "ss":
            $port = $input["server_port"];
            break;
    }
    return $port;
}

function ping($ip, $port)
{
    $start = microtime(true);
    $timeout = 0.5;
    $context = stream_context_create([
        'socket' => [
            'bindto' => '0:0',
        ]
    ]);
    $fp = @stream_socket_client(
        "tcp://$ip:$port",
        $errno,
        $errstr,
        $timeout,
        STREAM_CLIENT_CONNECT,
        $context
    );
    $end = microtime(true);

    if ($fp) {
        fclose($fp);
        return round(($end - $start) * 1000, 2);
    }
    return "unavailable";
}

// تابع جدید برای تولید نام بدون پینگ و با عدد تصادفی
function generate_name($flag, $is_reality)
{
    // تولید عدد تصادفی 4 رقمی
    $unique_id = rand(1000, 9999);
    
    $name = "";
    switch ($is_reality) {
        case true:
            $name = "R | " . $flag . " | @VPNineh | " . $unique_id;
            break;
        case false:
            $name = $flag . " | @VPNineh | " . $unique_id;
            break;
    }
    return $name;
}

// تابع کمکی برای ایجاد امضای منحصر به فرد جهت حذف تکراری‌ها
function get_config_signature($config, $type)
{
    $signature = "";
    switch ($type) {
        case "vmess":
            $signature = $config['add'] . ":" . $config['port'] . ":" . $config['id'];
            break;
        case "vless":
        case "trojan":
            $host = !empty($config['params']['sni']) ? $config['params']['sni'] : $config['hostname'];
            $signature = $host . ":" . $config['port'] . ":" . $config['username'];
            break;
        case "ss":
            $signature = $config['server_address'] . ":" . $config['server_port'] . ":" . $config['password'];
            break;
    }
    return md5($signature);
}

function process_config($config)
{
    global $seen_signatures; // دسترسی به آرایه جهانی

    $name_array = [
        "vmess" => "ps",
        "vless" => "hash",
        "trojan" => "hash",
        "ss" => "name",
    ];

    $type = detect_type($config);
    if (empty($type)) return false;

    $parsed_config = parse_config($config);

    // --- شروع منطق حذف تکراری ---
    // ایجاد یک امضای یکتا برای کانفیگ فعلی
    $signature = get_config_signature($parsed_config, $type);
    
    // اگر قبلاً این امضا را دیده‌ایم، این کانفیگ تکراری است و رد می‌شود
    if (in_array($signature, $seen_signatures)) {
        return false;
    }
    // امضا را به لیست دیده‌شده‌ها اضافه کن
    $seen_signatures[] = $signature;
    // --- پایان منطق حذف تکراری ---

    $is_reality = stripos($config, "reality") !== false ? true : false;
    $ip = get_ip($parsed_config, $type, $is_reality);
    $port = get_port($parsed_config, $type);
    
    // پینگ فقط برای چک کردن زنده بودن سرور استفاده می‌شود
    $ping_data = ping($ip, $port);
    
    if ($ping_data !== "unavailable") {
        $flag = get_flag($ip);
        $name_key = $name_array[$type];
        
        // فراخوانی تابع جدید نام‌گذاری (بدون ارسال پینگ)
        $parsed_config[$name_key] = generate_name($flag, $is_reality);
        
        $final_config = build_config($parsed_config, $type);
        return $final_config;
    }
    return false;
}

function is_base64_encoded($string)
{
    if (base64_encode(base64_decode($string, true)) === $string) {
        return "true";
    } else {
        return "false";
    }
}

function process_subscriptions($input)
{
    $output = [];
    if (is_base64_encoded($input) === "true") {
        $data = base64_decode($input);
        $output = process_subscriptions_helper($data);
    } else {
        $output = process_subscriptions_helper($input);
    }
    return $output;
}

function process_subscriptions_helper($input)
{
    $output = [];
    $data_array = explode("\n", $input);
    
    foreach ($data_array as $config) {
        $config = trim($config);
        if (empty($config)) continue;

        $processed_config = process_config($config);
        if ($processed_config !== false) {
            $type = detect_type($processed_config);
            switch ($type) {
                case "vmess":
                    $output["vmess"][] = $processed_config;
                    break;
                case "vless":
                    $output["vless"][] = $processed_config;
                    break;
                case "trojan":
                    $output["trojan"][] = $processed_config;
                    break;
                case "ss":
                    $output["ss"][] = $processed_config;
                    break;
            }
        }
    }
    return $output;
}

function merge_subscription($input)
{
    global $seen_signatures;
    $seen_signatures = []; // ریست کردن لیست تکراری‌ها برای هر بار اجرای کلی

    $output = [];
    $vmess = "";
    $vless = "";
    $trojan = "";
    $shadowsocks = "";

    foreach ($input as $subscription_url) {
        $subscription_data = @file_get_contents($subscription_url);
        if($subscription_data) {
            $processed_array = process_subscriptions($subscription_data);
            $vmess .= isset($processed_array["vmess"])
                ? implode("\n", $processed_array["vmess"]) . "\n"
                : null;
            $vless .= isset($processed_array["vless"])
                ? implode("\n", $processed_array["vless"]) . "\n"
                : null;
            $trojan .= isset($processed_array["trojan"])
                ? implode("\n", $processed_array["trojan"]) . "\n"
                : null;
            $shadowsocks .= isset($processed_array["ss"])
                ? implode("\n", $processed_array["ss"]) . "\n"
                : null;
        }
    }
    $output['vmess'] = array_filter(explode("\n", $vmess));
    $output['vless'] = array_filter(explode("\n", $vless));
    $output['trojan'] = array_filter(explode("\n", $trojan));
    $output['ss'] = array_filter(explode("\n", $shadowsocks));
    return $output;
}

function array_to_subscription($input) {
    return implode("\n", $input);
}
?>
