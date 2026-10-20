<?php

/*
 * IPsec Tunnelmatch GNS3 lab: applies the plan to an OPNsense node.
 *
 *   php opnsense_apply.php /tmp/tmlab.json
 *
 * Runs on the firewall itself (console shell, option 8). Uses the same MVC models
 * the GUI and API use (OPNsense\IPsec\Swanctl and OPNsense\IPsec\IPsec), so the
 * models validate the proposal strings: a value the GUI would not accept fails here.
 * Prints TMLAB-OK, or TMLAB-INVALID lines and exits 1.
 *
 * Field names checked against opnsense/core master (2026-10-20).
 */

require_once('/usr/local/opnsense/mvc/script/load_phalcon.php');

use OPNsense\Core\Config;

$in = json_decode(file_get_contents($argv[1]), true);
if (!is_array($in)) {
    echo "TMLAB-INVALID input: cannot read {$argv[1]}\n";
    exit(1);
}

/* 1. Interfaces and IPsec on/off live in the legacy part of config.xml. */
Config::getInstance()->lock();
$cfg = Config::getInstance()->object();
$cfg->interfaces->wan->if = $in['wan_if'];
$cfg->interfaces->wan->ipaddr = $in['wan_ip'];
$cfg->interfaces->wan->subnet = (string)$in['wan_prefix'];
unset($cfg->interfaces->wan->blockpriv);
unset($cfg->interfaces->wan->blockbogons); // 203.0.113.0/24 is a documentation (bogon) range
$cfg->interfaces->lan->if = $in['lan_if'];
$cfg->interfaces->lan->ipaddr = $in['lan_ip'];
$cfg->interfaces->lan->subnet = (string)$in['lan_prefix'];
$cfg->ipsec->enable = true;
Config::getInstance()->save();

/* 2. Connections, authentication rounds, children and keys through the models. */
$sw = new \OPNsense\IPsec\Swanctl();
$ipsec = new \OPNsense\IPsec\IPsec();

foreach ($in['connections'] as $c) {
    $conn = $sw->Connections->Connection->Add();
    $conn->setNodes([
        'enabled' => '1',
        'description' => $c['description'],
        'version' => '2',
        'proposals' => $c['proposals'],
        'local_addrs' => $c['local_addrs'],
        'remote_addrs' => $c['remote_addrs'],
        'unique' => $c['unique'],
        'dpd_delay' => $c['dpd_delay'],
        'rekey_time' => $c['rekey_time'],
    ]);
    $uuid = $conn->getAttribute('uuid');

    $sw->locals->local->Add()->setNodes([
        'enabled' => '1', 'connection' => $uuid, 'round' => '0', 'auth' => 'psk', 'id' => $c['local_id'],
    ]);
    $sw->remotes->remote->Add()->setNodes([
        'enabled' => '1', 'connection' => $uuid, 'round' => '0', 'auth' => 'psk', 'id' => $c['remote_id'],
    ]);
    foreach ($c['children'] as $i => $ch) {
        $sw->children->child->Add()->setNodes([
            'enabled' => '1',
            'connection' => $uuid,
            'description' => $c['description'] . ' ' . ($i + 1),
            'mode' => 'tunnel',
            'policies' => $ch['policies'],
            'local_ts' => $ch['local_ts'],
            'remote_ts' => $ch['remote_ts'],
            'esp_proposals' => $ch['esp_proposals'],
            'start_action' => $ch['start_action'],
            'rekey_time' => $ch['rekey_time'],
        ]);
    }
    $ipsec->preSharedKeys->preSharedKey->Add()->setNodes([
        'ident' => $c['local_id'],
        'remote_ident' => $c['remote_id'],
        'keyType' => 'PSK',
        'Key' => $c['psk'],
        'description' => $c['description'],
    ]);
}

/* 3. Let the tunnel traffic in on the IPsec interface (enc0). */
$filter = new \OPNsense\Firewall\Filter();
$filter->rules->rule->Add()->setNodes([
    'enabled' => '1',
    'action' => 'pass',
    'quick' => '1',
    'interface' => 'enc0',
    'direction' => 'in',
    'ipprotocol' => 'inet',
    'protocol' => 'any',
    'source_net' => 'any',
    'destination_net' => 'any',
    'description' => 'tmlab: allow IPsec traffic',
]);

$bad = 0;
foreach (['swanctl' => $sw, 'ipsec' => $ipsec, 'filter' => $filter] as $name => $mdl) {
    foreach ($mdl->performValidation() as $msg) {
        echo "TMLAB-INVALID {$name} " . $msg->getField() . ": " . $msg->getMessage() . "\n";
        $bad++;
    }
}
if ($bad) {
    Config::getInstance()->unlock();
    exit(1);
}
$sw->serializeToConfig();
$ipsec->serializeToConfig();
$filter->serializeToConfig();
Config::getInstance()->save();
echo "TMLAB-OK " . count($in['connections']) . " connections\n";
