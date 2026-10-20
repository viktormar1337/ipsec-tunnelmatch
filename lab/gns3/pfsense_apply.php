<?php

/*
 * IPsec Tunnelmatch GNS3 lab: applies the plan to a pfSense node.
 *
 *   php pfsense_apply.php /tmp/tmlab.json
 *
 * Runs on the firewall itself (console menu option 8). Writes the same config.xml
 * structures the Tunnels pages write (vpn_ipsec_phase1.php / vpn_ipsec_phase2.php,
 * pfSense 2.7.2): ipsec/phase1 with encryption/item, ipsec/phase2 with
 * encryption-algorithm-option and hash-algorithm-option. The page validation is not
 * run here, so a value the GUI would reject is not caught; the values come from the
 * tool's pfSense field list, mapped in generate.js.
 * Prints TMLAB-OK, or TMLAB-INVALID lines and exits 1.
 */

require_once("config.inc");
require_once("util.inc");
require_once("ipsec.inc");

$in = json_decode(file_get_contents($argv[1]), true);
if (!is_array($in)) {
    echo "TMLAB-INVALID input: cannot read {$argv[1]}\n";
    exit(1);
}

/* Interfaces: WAN and LAN addresses; 203.0.113.0/24 is a documentation (bogon) range. */
$wan = config_get_path('interfaces/wan', []);
$wan['if'] = $in['wan_if'];
$wan['ipaddr'] = $in['wan_ip'];
$wan['subnet'] = (string)$in['wan_prefix'];
unset($wan['blockpriv'], $wan['blockbogons'], $wan['gateway']);
config_set_path('interfaces/wan', $wan);

$lan = config_get_path('interfaces/lan', []);
$lan['if'] = $in['lan_if'];
$lan['ipaddr'] = $in['lan_ip'];
$lan['subnet'] = (string)$in['lan_prefix'];
config_set_path('interfaces/lan', $lan);
config_del_path('dhcpd/lan'); // the default DHCP range no longer fits the LAN

/* IPsec phase 1 and phase 2 entries, as the Tunnels pages store them. */
$ph1s = [];
$ph2s = [];
$reqid = 1;
foreach ($in['tunnels'] as $i => $t) {
    $ikeid = $i + 1;
    $bad = [];
    if (!isset($p1_ealgos[$t['enc']['name']])) $bad[] = "phase 1 encryption {$t['enc']['name']}";
    if (!isset($p1_halgos[$t['hash']])) $bad[] = "phase 1 hash {$t['hash']}";
    if (!isset($p1_dhgroups[$t['dhgroup']])) $bad[] = "DH group {$t['dhgroup']}";
    $ph1s[] = [
        'ikeid' => (string)$ikeid,
        'iketype' => 'ikev2',
        'interface' => 'wan',
        'remote-gateway' => $t['remote'],
        'protocol' => 'inet',
        'myid_type' => 'myaddress',
        'myid_data' => '',
        'peerid_type' => 'peeraddress',
        'peerid_data' => '',
        'encryption' => ['item' => [[
            'encryption-algorithm' => ['name' => $t['enc']['name'], 'keylen' => (string)$t['enc']['keylen']],
            'hash-algorithm' => $t['hash'],
            'prf-algorithm' => $t['hash'],
            'dhgroup' => $t['dhgroup'],
        ]]],
        'lifetime' => $t['lifetime'],
        'rekey_time' => $t['rekey_time'],
        'reauth_time' => '',
        'rand_time' => '',
        'pre-shared-key' => $t['psk'],
        'authentication_method' => 'pre_shared_key',
        'descr' => $t['descr'],
        'nat_traversal' => 'on',
        'mobike' => 'off',
        'startaction' => '',
        'closeaction' => '',
        'dpd_delay' => $t['dpd_delay'],
        'dpd_maxfail' => $t['dpd_maxfail'],
    ];
    foreach ($t['phase2'] as $j => $p) {
        if (!isset($p2_ealgos[$p['enc']['name']])) $bad[] = "phase 2 encryption {$p['enc']['name']}";
        if ($p['hash'] !== null && !isset($p2_halgos[$p['hash']])) $bad[] = "phase 2 hash {$p['hash']}";
        if ($p['pfsgroup'] !== '0' && !isset($p1_dhgroups[$p['pfsgroup']])) $bad[] = "PFS group {$p['pfsgroup']}";
        $ph2 = [
            'ikeid' => (string)$ikeid,
            'uniqid' => uniqid(),
            'mode' => 'tunnel',
            'reqid' => (string)$reqid++,
            'localid' => $p['localid'],
            'remoteid' => $p['remoteid'],
            'protocol' => 'esp',
            'encryption-algorithm-option' => [['name' => $p['enc']['name'], 'keylen' => (string)$p['enc']['keylen']]],
            'pfsgroup' => $p['pfsgroup'],
            'lifetime' => $p['lifetime'],
            'rekey_time' => $p['rekey_time'],
            'rand_time' => '',
            'keepalive' => 'disabled',
            'descr' => $t['descr'] . ' ' . ($j + 1),
        ];
        if ($p['hash'] !== null) {
            $ph2['hash-algorithm-option'] = [$p['hash']];
        }
        $ph2s[] = $ph2;
    }
    foreach ($bad as $b) {
        echo "TMLAB-INVALID {$t['descr']}: {$b} is not offered by this pfSense version\n";
    }
    if ($bad) {
        exit(1);
    }
}
config_set_path('ipsec/phase1', $ph1s);
config_set_path('ipsec/phase2', $ph2s);

/* Let the tunnel traffic in on the IPsec tab (enc0). */
$rules = config_get_path('filter/rule', []);
$rules[] = [
    'type' => 'pass',
    'interface' => 'enc0',
    'ipprotocol' => 'inet',
    'protocol' => '',
    'source' => ['any' => ''],
    'destination' => ['any' => ''],
    'descr' => 'tmlab: allow IPsec traffic',
    'tracker' => (string)time(),
];
config_set_path('filter/rule', $rules);

write_config("IPsec Tunnelmatch lab");
echo "TMLAB-OK " . count($ph1s) . " phase 1, " . count($ph2s) . " phase 2\n";
