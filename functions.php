<?php
/** =========================
 *  Detect Type of Config
 *  ========================= */
function detect_type($input)
{
    $input = trim((string)$input);
    if (substr($input, 0, 8) === "vmess://") return "vmess";
    if (substr($input, 0, 8) === "vless://") return "vless";
    if (substr($input, 0, 9) === "trojan://") return "trojan";
    if (substr($input, 0, 5) === "ss://") return "ss";
    return "";
}

function parse_config($input)
{
    $type = detect_type($input);
    switch ($type) {
        case "vmess":
            return decode_vmess($input);
        case "vless":
        case "trojan":
            return parseProxyUrl($input, $type);
        case "ss":
            return ParseShadowsocks($input);
        default:
            return [];
    }
}

function build_config($input, $type)
{
    switch ($type) {
        case "vmess":
            return encode_vmess($input);
        case "vless":
        case "trojan":
            return buildProxyUrl($input, $type);
        case "ss":
            return BuildShadowsocks($input);
        default:
            return "";
    }
}

/** =========================
 *  vmess parse/build
 *  ========================= */
function decode_vmess($vmess_config)
{
    $vmess_config = trim((string)$vmess_config);
    $vmess_data = substr($vmess_config, 8); // remove "vmess://"
    $decoded = base64_decode($vmess_data, true);
    if ($decoded === false) return [];
    $decoded_data = json_decode($decoded, true);
    return is_array($decoded_data) ? $decoded_data : [];
}

function encode_vmess($config)
{
    $encoded_data = base64_encode(json_encode($config, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE));
    return "vmess://" . $encoded_data;
}

/** remove duplicate vmess configs (old-style, still usable) */
function remove_duplicate_vmess($input)
{
    $array = preg_split("/\r\n|\r|\n/", (string)$input);
    $result = [];

    foreach ($array as $item) {
        $item = trim($item);
        if ($item === "") continue;

        $parts = decode_vmess($item);
        if (!empty($parts)) {
            $part_ps = $parts["ps"] ?? "";
            unset($parts["ps"]);
            if (count($parts) >= 3) {
                ksort($parts);
                $part_serialize = serialize($parts);
                $result[$part_serialize][] = $part_ps;
            }
        }
    }

    $finalResult = [];
    foreach ($result as $serial => $ps) {
        $partAfterHash = $ps[0] ?? "";
        $part_serialize = unserialize($serial);
        $part_serialize["ps"] = $partAfterHash;
        $finalResult[] = encode_vmess($part_serialize);
    }

    return implode("\n", $finalResult);
}

/** =========================
 *  vless/trojan parse/build
 *  ========================= */
function parseProxyUrl($url, $type = "trojan")
{
    $url = trim((string)$url);
    $parsedUrl = parse_url($url);
    if (!is_array($parsedUrl)) return [];

    $params = [];
    if (isset($parsedUrl["query"])) {
        parse_str($parsedUrl["query"], $params);
    }

    return [
        "protocol" => $type,
        "username" => $parsedUrl["user"] ?? "",
        "pass" => $parsedUrl["pass"] ?? "",
        "hostname" => $parsedUrl["host"] ?? "",
        "port" => $parsedUrl["port"] ?? "",
        "params" => $params,
        "hash" => $parsedUrl["fragment"] ?? "",
    ];
}

function buildProxyUrl($obj, $type = "trojan")
{
    $url = $type . "://";
    $url .= addUsernameAndPassword($obj);
    $url .= $obj["hostname"] ?? "";
    $url .= addPort($obj);
    $url .= addParams($obj);
    $url .= addHash($obj);
    return $url;
}

function addUsernameAndPassword($obj)
{
    $url = "";
    $u = $obj["username"] ?? "";
    if ($u !== "") {
        $url .= $u;
        $p = $obj["pass"] ?? "";
        if ($p !== "") $url .= ":" . $p;
        $url .= "@";
    }
    return $url;
}

function addPort($obj)
{
    $port = $obj["port"] ?? "";
    return ($port !== "") ? ":" . $port : "";
}

function addParams($obj)
{
    $params = $obj["params"] ?? [];
    if (!is_array($params) || empty($params)) return "";
    return "?" . http_build_query($params);
}

function addHash($obj)
{
    $hash = $obj["hash"] ?? "";
    return ($hash !== "") ? "#" . $hash : "";
}

/** remove duplicate vless/trojan configs (old-style, fixed) */
function remove_duplicate_xray($input, $type)
{
    $array = preg_split("/\r\n|\r|\n/", (string)$input);
    $result = [];

    foreach ($array as $item) {
        $item = trim($item);
        if ($item === "") continue;

        $parts = parseProxyUrl($item, $type);
        if (empty($parts)) continue;

        $part_hash = $parts["hash"] ?? "";
        unset($parts["hash"]);

        if (!isset($parts["params"]) || !is_array($parts["params"])) $parts["params"] = [];
        ksort($parts["params"]);

        $part_serialize = serialize($parts);
        $result[$part_serialize][] = $part_hash;
    }

    $finalResult = [];
    foreach ($result as $url => $parts) {
        $partAfterHash = $parts[0] ?? "";
        $part_serialize = unserialize($url);
        $part_serialize["hash"] = $partAfterHash;
        $finalResult[] = buildProxyUrl($part_serialize, $type);
    }

    return implode("\n", $finalResult);
}

/** =========================
 *  Shadowsocks parse/build
 *  ========================= */
function ParseShadowsocks($config_str)
{
    $config_str = trim((string)$config_str);
    $url = parse_url($config_str);
    if (!is_array($url) || !isset($url["user"]) || !isset($url["host"]) || !isset($url["port"])) return [];

    $userDecoded = base64_decode($url["user"], true);
    if ($userDecoded === false) return [];

    $parts = explode(":", $userDecoded, 2);
    if (count($parts) !== 2) return [];

    $encryption_method = $parts[0];
    $password = $parts[1];

    $server_address = $url["host"];
    $server_port = $url["port"];
    $name = isset($url["fragment"]) ? urldecode($url["fragment"]) : null;

    return [
        "encryption_method" => $encryption_method,
        "password" => $password,
        "server_address" => $server_address,
        "server_port" => $server_port,
        "name" => $name,
    ];
}

function BuildShadowsocks($server)
{
    $user = base64_encode(($server["encryption_method"] ?? "") . ":" . ($server["password"] ?? ""));
    $url = "ss://$user@{$server["server_address"]}:{$server["server_port"]}";
    if (!empty($server["name"])) $url .= "#" . urlencode($server["name"]);
    return $url;
}

/** remove duplicate shadowsocks configs (old-style, fixed) */
function remove_duplicate_ss($input)
{
    $array = preg_split("/\r\n|\r|\n/", (string)$input);
    $result = [];

    foreach ($array as $item) {
        $item = trim($item);
        if ($item === "") continue;

        $parts = ParseShadowsocks($item);
        if (empty($parts)) continue;

        $part_hash = $parts["name"] ?? "";
        unset($parts["name"]);
        ksort($parts);

        $part_serialize = serialize($parts);
        $result[$part_serialize][] = $part_hash;
    }

    $finalResult = [];
    foreach ($result as $url => $parts) {
        $partAfterHash = $parts[0] ?? "";
        $part_serialize = unserialize($url);
        $part_serialize["name"] = $partAfterHash;
        $finalResult[] = BuildShadowsocks($part_serialize);
    }

    return implode("\n", $finalResult);
}

/** =========================
 *  IP + Flag helpers
 *  ========================= */
function is_ip($string)
{
    $ipv4_pattern = '/^\d{1,3}(\.\d{1,3}){3}$/';
    $ipv6_pattern = '/^[0-9a-fA-F:]+$/';
    return (bool)(preg_match($ipv4_pattern, $string) || preg_match($ipv6_pattern, $string));
}

function ip_info($ip)
{
    $ip = trim((string)$ip);

    if (!is_ip($ip)) {
        $ip_address_array = @dns_get_record($ip, DNS_A);
        if (is_array($ip_address_array) && !empty($ip_address_array)) {
            $randomKey = array_rand($ip_address_array);
            $ip = $ip_address_array[$randomKey]["ip"] ?? $ip;
        }
    }

    $resp = @file_get_contents("https://api.country.is/" . $ip);
    if ($resp === false) return [];
    $ipinfo = json_decode($resp, true);
    return is_array($ipinfo) ? $ipinfo : [];
}

function get_flag($ip)
{
    $ip_info = ip_info($ip);
    if (isset($ip_info["country"])) {
        $cc = $ip_info["country"];
        return $cc . getFlags($cc);
    }
    return "R 🚩";
}

function getFlags($country_code)
{
    $country_code = strtoupper((string)$country_code);
    if (strlen($country_code) !== 2) return "🏳️";

    $flag = mb_convert_encoding("&#" . (127397 + ord($country_code[0])) . ";", "UTF-8", "HTML-ENTITIES");
    $flag .= mb_convert_encoding("&#" . (127397 + ord($country_code[1])) . ";", "UTF-8", "HTML-ENTITIES");
    return $flag;
}

/** =========================
 *  Extract IP/Port + ping + name
 *  ========================= */
function get_ip($config, $type, $is_reality)
{
    switch ($type) {
        case "vmess": return get_vmess_ip($config);
        case "vless": return get_vless_ip($config, $is_reality);
        case "trojan": return get_trojan_ip($config);
        case "ss": return get_ss_ip($config);
        default: return "";
    }
}

function get_vmess_ip($input)
{
    return !empty($input["sni"]) ? $input["sni"] : (!empty($input["host"]) ? $input["host"] : ($input["add"] ?? ""));
}

function get_vless_ip($input, $is_reality)
{
    if ($is_reality) return $input["hostname"] ?? "";
    return !empty($input["params"]["sni"]) ? $input["params"]["sni"] : (!empty($input["params"]["host"]) ? $input["params"]["host"] : ($input["hostname"] ?? ""));
}

function get_trojan_ip($input)
{
    return !empty($input["params"]["sni"]) ? $input["params"]["sni"] : (!empty($input["params"]["host"]) ? $input["params"]["host"] : ($input["hostname"] ?? ""));
}

function get_ss_ip($input)
{
    return $input["server_address"] ?? "";
}

function get_port($input, $type)
{
    switch ($type) {
        case "vmess": return $input["port"] ?? "";
        case "vless": return $input["port"] ?? "";
        case "trojan": return $input["port"] ?? "";
        case "ss": return $input["server_port"] ?? "";
        default: return "";
    }
}

function ping($ip, $port)
{
    $ip = trim((string)$ip);
    $port = intval($port);
    if ($ip === "" || $port <= 0) return "unavailable";

    $it = microtime(true);
    $check = @fsockopen($ip, $port, $errno, $errstr, 0.5);
    $ft = microtime(true);

    $militime = round(($ft - $it) * 1e3, 2);
    if ($check) {
        fclose($check);
        return $militime;
    }
    return "unavailable";
}

function generate_name($flag, $ip, $port, $ping, $is_reality)
{
    return $is_reality ? ("R | " . $flag . " | " . " @VPNineh" . " | " . $ping)
                       : ($flag . " | " . "@VPNineh" . " | " . $ping);
}

function process_config($config)
{
    $name_array = [
        "vmess" => "ps",
        "vless" => "hash",
        "trojan" => "hash",
        "ss" => "name",
    ];

    $config = trim((string)$config);
    if ($config === "") return false;

    $type = detect_type($config);
    if ($type === "") return false;

    $is_reality = (stripos($config, "reality") !== false);

    $parsed_config = parse_config($config);
    if (empty($parsed_config)) return false;

    $ip = get_ip($parsed_config, $type, $is_reality);
    $port = get_port($parsed_config, $type);

    $ping_data = ping($ip, $port);
    if ($ping_data === "unavailable") return false;

    $flag = get_flag($ip);
    $name_key = $name_array[$type];

    $parsed_config[$name_key] = generate_name($flag, $ip, $port, $ping_data, $is_reality);
    return build_config($parsed_config, $type);
}

/** =========================
 *  Reality extractor (fixed)
 *  ========================= */
function get_reality($input)
{
    $array = preg_split("/\r\n|\r|\n/", (string)$input);
    $output = [];
    foreach ($array as $item) {
        $item = trim($item);
        if ($item === "") continue;
        if (stripos($item, "reality") !== false) $output[] = $item;
    }
    return implode("\n", $output);
}

/** =========================
 *  base64 check
 *  ========================= */
function is_base64_encoded($string)
{
    $string = trim((string)$string);
    if ($string === "") return false;
    $decoded = base64_decode($string, true);
    if ($decoded === false) return false;
    return base64_encode($decoded) === $string;
}

/** =========================
 *  subscriptions processing
 *  ========================= */
function process_subscriptions($input)
{
    $input = (string)$input;
    if (is_base64_encoded($input)) {
        $data = base64_decode($input, true);
        if ($data === false) return [];
        return process_subscriptions_helper($data);
    }
    return process_subscriptions_helper($input);
}

function process_subscriptions_helper($input)
{
    $output = [];
    $data_array = preg_split("/\r\n|\r|\n/", (string)$input);

    foreach ($data_array as $config) {
        $config = trim($config);
        if ($config === "") continue;

        $processed_config = process_config($config);
        if ($processed_config === false) continue;

        $type = detect_type($processed_config);
        if ($type === "") continue;

        $output[$type][] = $processed_config;
    }
    return $output;
}

function array_to_subscription($input) {
    return implode("\n", (array)$input);
}

/** =========================
 *  ✅ PRO DEDUP (حذف تکراری حرفه‌ای)
 *  ========================= */
function normalize_host($h) {
    $h = strtolower(trim((string)$h));
    return rtrim($h, ".");
}
function normalize_port($p) {
    $p = trim((string)$p);
    return $p === "" ? "" : (string)intval($p);
}
function sort_params_recursively(&$arr) {
    if (!is_array($arr)) return;
    ksort($arr);
    foreach ($arr as &$v) {
        if (is_array($v)) sort_params_recursively($v);
    }
}
function safe_trim_lines($input) {
    $lines = preg_split("/\r\n|\r|\n/", (string)$input);
    $out = [];
    foreach ($lines as $l) {
        $l = trim($l);
        if ($l !== "") $out[] = $l;
    }
    return $out;
}

/** Fingerprint پایدار: مستقل از name/ps/hash و ترتیب params */
function config_fingerprint($config_str) {
    $type = detect_type($config_str);
    if ($type === "") return false;

    if ($type === "vmess") {
        $obj = decode_vmess($config_str);
        if (!is_array($obj) || empty($obj)) return false;

        unset($obj["ps"]); // ignore display name

        if (isset($obj["add"])) $obj["add"] = normalize_host($obj["add"]);
        if (isset($obj["host"])) $obj["host"] = normalize_host($obj["host"]);
        if (isset($obj["sni"])) $obj["sni"] = normalize_host($obj["sni"]);
        if (isset($obj["port"])) $obj["port"] = normalize_port($obj["port"]);

        ksort($obj);
        return "vmess|" . hash("sha256", json_encode($obj, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE));
    }

    if ($type === "vless" || $type === "trojan") {
        $obj = parseProxyUrl($config_str, $type);
        if (!is_array($obj) || empty($obj)) return false;

        unset($obj["hash"]); // ignore display name

        $obj["hostname"] = normalize_host($obj["hostname"] ?? "");
        $obj["port"] = normalize_port($obj["port"] ?? "");

        $obj["username"] = (string)($obj["username"] ?? "");
        $obj["pass"] = (string)($obj["pass"] ?? "");

        if (!isset($obj["params"]) || !is_array($obj["params"])) $obj["params"] = [];
        foreach (["sni","host"] as $k) {
            if (isset($obj["params"][$k])) $obj["params"][$k] = normalize_host($obj["params"][$k]);
        }
        sort_params_recursively($obj["params"]);

        ksort($obj);
        return $type . "|" . hash("sha256", json_encode($obj, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE));
    }

    if ($type === "ss") {
        $obj = ParseShadowsocks($config_str);
        if (!is_array($obj) || empty($obj)) return false;

        unset($obj["name"]); // ignore display name

        $obj["server_address"] = normalize_host($obj["server_address"] ?? "");
        $obj["server_port"] = normalize_port($obj["server_port"] ?? "");

        ksort($obj);
        return "ss|" . hash("sha256", json_encode($obj, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE));
    }

    return false;
}

/** Dedup متن کانفیگ‌ها (هر خط یک کانفیگ) */
function dedup_subscription_text($input_text) {
    $lines = safe_trim_lines($input_text);
    $seen = [];
    $out = [];

    foreach ($lines as $line) {
        $fp = config_fingerprint($line);
        if ($fp === false) continue;
        if (isset($seen[$fp])) continue;
        $seen[$fp] = true;
        $out[] = $line;
    }

    return implode("\n", $out);
}

/** Dedup آرایه‌های per-type */
function dedup_subscription_arrays($output) {
    $joined = [
        "vmess"  => isset($output["vmess"])  ? implode("\n", array_filter($output["vmess"]))  : "",
        "vless"  => isset($output["vless"])  ? implode("\n", array_filter($output["vless"]))  : "",
        "trojan" => isset($output["trojan"]) ? implode("\n", array_filter($output["trojan"])) : "",
        "ss"     => isset($output["ss"])     ? implode("\n", array_filter($output["ss"]))     : "",
    ];

    foreach ($joined as $k => $txt) {
        $joined[$k] = dedup_subscription_text($txt);
    }

    return [
        "vmess"  => $joined["vmess"]  === "" ? [] : safe_trim_lines($joined["vmess"]),
        "vless"  => $joined["vless"]  === "" ? [] : safe_trim_lines($joined["vless"]),
        "trojan" => $joined["trojan"] === "" ? [] : safe_trim_lines($joined["trojan"]),
        "ss"     => $joined["ss"]     === "" ? [] : safe_trim_lines($joined["ss"]),
    ];
}

/** =========================
 *  ✅ merge_subscription نهایی + PRO DEDUP
 *  ========================= */
function merge_subscription($input)
{
    $output = [
        "vmess" => [],
        "vless" => [],
        "trojan" => [],
        "ss" => [],
    ];

    foreach ((array)$input as $subscription_url) {
        $subscription_data = @file_get_contents($subscription_url);
        if ($subscription_data === false || trim($subscription_data) === "") continue;

        $processed_array = process_subscriptions($subscription_data);

        if (!empty($processed_array["vmess"]))  $output["vmess"]  = array_merge($output["vmess"],  $processed_array["vmess"]);
        if (!empty($processed_array["vless"]))  $output["vless"]  = array_merge($output["vless"],  $processed_array["vless"]);
        if (!empty($processed_array["trojan"])) $output["trojan"] = array_merge($output["trojan"], $processed_array["trojan"]);
        if (!empty($processed_array["ss"]))     $output["ss"]     = array_merge($output["ss"],     $processed_array["ss"]);
    }

    // ✅ حذف تکراری حرفه‌ای
    return dedup_subscription_arrays($output);
}
