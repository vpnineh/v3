<?php

/* =======================
   Detect config type
======================= */
function detect_type($input)
{
    if (substr($input, 0, 8) === "vmess://") return "vmess";
    if (substr($input, 0, 8) === "vless://") return "vless";
    if (substr($input, 0, 9) === "trojan://") return "trojan";
    if (substr($input, 0, 5) === "ss://") return "ss";
    return "";
}

/* =======================
   Parse / Build
======================= */
function parse_config($input)
{
    $type = detect_type($input);
    if ($type === "vmess") return decode_vmess($input);
    if ($type === "vless" || $type === "trojan") return parseProxyUrl($input);
    if ($type === "ss") return ParseShadowsocks($input);
    return null;
}

function build_config($input, $type)
{
    if ($type === "vmess") return encode_vmess($input);
    if ($type === "vless" || $type === "trojan") return buildProxyUrl($input, $type);
    if ($type === "ss") return BuildShadowsocks($input);
    return "";
}

/* =======================
   VMESS
======================= */
function decode_vmess($vmess)
{
    return json_decode(base64_decode(substr($vmess, 8)), true);
}

function encode_vmess($config)
{
    return "vmess://" . base64_encode(json_encode($config, JSON_UNESCAPED_UNICODE));
}

/* =======================
   VLESS / TROJAN
======================= */
function parseProxyUrl($url)
{
    $u = parse_url($url);
    parse_str(isset($u['query']) ? $u['query'] : '', $params);

    return [
        "username" => isset($u['user']) ? $u['user'] : '',
        "hostname" => isset($u['host']) ? $u['host'] : '',
        "port" => isset($u['port']) ? $u['port'] : '',
        "params" => $params,
        "hash" => isset($u['fragment']) ? $u['fragment'] : ''
    ];
}

function buildProxyUrl($o, $type)
{
    $url = $type . "://";
    if (!empty($o['username'])) $url .= $o['username'] . "@";
    $url .= $o['hostname'];
    if (!empty($o['port'])) $url .= ":" . $o['port'];
    if (!empty($o['params'])) $url .= "?" . http_build_query($o['params']);
    if (!empty($o['hash'])) $url .= "#" . $o['hash'];
    return $url;
}

/* =======================
   SHADOWSOCKS
======================= */
function ParseShadowsocks($c)
{
    $u = parse_url($c);
    $decoded = base64_decode($u['user']);
    list($method, $pass) = explode(":", $decoded, 2);

    return [
        "encryption_method" => $method,
        "password" => $pass,
        "server_address" => $u['host'],
        "server_port" => $u['port'],
        "name" => isset($u['fragment']) ? urldecode($u['fragment']) : ''
    ];
}

function BuildShadowsocks($s)
{
    $user = base64_encode($s['encryption_method'] . ":" . $s['password']);
    $url = "ss://{$user}@{$s['server_address']}:{$s['server_port']}";
    if (!empty($s['name'])) $url .= "#" . urlencode($s['name']);
    return $url;
}

/* =======================
   IP / LOCATION
======================= */
function is_ip($s)
{
    return filter_var($s, FILTER_VALIDATE_IP) !== false;
}

function ip_info($ip)
{
    if (!is_ip($ip)) {
        $records = dns_get_record($ip, DNS_A);
        if (!$records) return null;
        $ip = $records[array_rand($records)]['ip'];
    }

    $url = "https://api.iplocation.io/?ip={$ip}";
    $context = stream_context_create([
        'http' => ['timeout' => 2]
    ]);

    $response = @file_get_contents($url, false, $context);
    if ($response === false) return null;

    $data = json_decode($response, true);
    return is_array($data) ? $data : null;
}

function get_flag($ip)
{
    $info = ip_info($ip);
    if (!$info || empty($info['country_code2'])) return "XX 🚩";

    $cc = strtoupper($info['country_code2']);
    return $cc . getFlags($cc);
}

function getFlags($cc)
{
    return mb_convert_encoding(
        "&#" . (127397 + ord($cc[0])) . ";&#" . (127397 + ord($cc[1])) . ";",
        "UTF-8",
        "HTML-ENTITIES"
    );
}

/* =======================
   IP / PORT
======================= */
function get_ip($c, $type, $reality)
{
    if ($type === "vmess") return !empty($c['sni']) ? $c['sni'] : (!empty($c['host']) ? $c['host'] : $c['add']);
    if ($type === "vless") return $reality ? $c['hostname'] : (!empty($c['params']['sni']) ? $c['params']['sni'] : $c['hostname']);
    if ($type === "trojan") return !empty($c['params']['sni']) ? $c['params']['sni'] : $c['hostname'];
    if ($type === "ss") return $c['server_address'];
    return null;
}

function get_port($c, $type)
{
    return $type === "ss" ? $c['server_port'] : (isset($c['port']) ? $c['port'] : null);
}

/* =======================
   DEDUP CORE
======================= */
function generate_fingerprint($parsed, $type)
{
    $base = [
        'type' => $type,
        'host' => get_ip($parsed, $type, false),
        'port' => get_port($parsed, $type)
    ];

    if (isset($parsed['params'])) {
        ksort($parsed['params']);
        $base['params'] = $parsed['params'];
    }

    return hash('sha256', json_encode($base));
}

function short_id($fp)
{
    return substr((string)hexdec(substr($fp, 0, 6)), 0, 4);
}

/* =======================
   NAME
======================= */
function generate_name($flag, $id, $reality)
{
    return $reality
        ? "R | {$flag} | #{$id} @VPNineh"
        : "{$flag} | #{$id} @VPNineh";
}

/* =======================
   PROCESS CONFIG
======================= */
function process_config($config)
{
    $type = detect_type($config);
    if (!$type) return false;

    $parsed = parse_config($config);
    if (!$parsed) return false;

    $is_reality = stripos($config, "reality") !== false;
    $ip = get_ip($parsed, $type, $is_reality);
    $port = get_port($parsed, $type);
    if (!$ip || !$port) return false;

    $fp = generate_fingerprint($parsed, $type);
    $id = short_id($fp);
    $flag = get_flag($ip);

    if ($type === "vmess") $parsed['ps'] = generate_name($flag, $id, $is_reality);
    elseif ($type === "ss") $parsed['name'] = generate_name($flag, $id, $is_reality);
    else $parsed['hash'] = generate_name($flag, $id, $is_reality);

    return build_config($parsed, $type);
}

/* =======================
   SUBSCRIPTIONS
======================= */
function process_subscriptions($input)
{
    if (base64_encode(base64_decode($input, true)) === $input) {
        $input = base64_decode($input);
    }

    $seen = [];
    $out = [];

    foreach (explode("\n", $input) as $c) {
        $c = trim($c);
        if ($c === "") continue;

        $processed = process_config($c);
        if (!$processed) continue;

        $type = detect_type($processed);
        $fp = generate_fingerprint(parse_config($processed), $type);
        if (isset($seen[$fp])) continue;

        $seen[$fp] = true;
        $out[$type][] = $processed;
    }

    return $out;
}

function merge_subscription($urls)
{
    $out = [];
    foreach ($urls as $url) {
        $data = @file_get_contents($url);
        if (!$data) continue;

        $processed = process_subscriptions($data);
        foreach ($processed as $type => $list) {
            if (!isset($out[$type])) $out[$type] = [];
            $out[$type] = array_merge($out[$type], $list);
        }
    }
    return $out;
}
