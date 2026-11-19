<?php
/* BiXCore: restricted local FreeRADIUS user changes.
 * Actions: legacy Enabled/Disabled for VLAN users; set_vlan; portal_enabled
 * for a no-VLAN local account. This file is never an arbitrary API.
 */
require_once('config.inc');
use OPNsense\Freeradius\User;
use OPNsense\Core\Config;

function exactKeys(array $obj, array $required): bool {
    $actual=array_keys($obj);
    sort($actual);sort($required);
    return $actual === $required;
}
try {
    $raw=stream_get_contents(STDIN,4096);
    $arg=json_decode($raw,true,8,JSON_THROW_ON_ERROR);
    if (!is_array($arg)) throw new RuntimeException('INVALID_REQUEST');
    $action=$arg['action']??null;
    $vlanAction=($action==='set_vlan');
    $portalAction=($action==='portal_enabled');
    $guestAction=($action==='guest_enabled');
    if ($vlanAction) {
        if (!exactKeys($arg,['action','uuid','username','expected_vlan','vlan','expected_enabled']))
            throw new RuntimeException('INVALID_REQUEST');
    } elseif ($portalAction || $guestAction) {
        if (!exactKeys($arg,['action','uuid','username','expected_enabled','enabled']))
            throw new RuntimeException('INVALID_REQUEST');
    } elseif (!exactKeys($arg,['uuid','username','expected_enabled','enabled'])) {
        throw new RuntimeException('INVALID_REQUEST');
    }

    $uuid=$arg['uuid'];$name=$arg['username'];
    if (!is_string($uuid) ||
        !preg_match('/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/D',$uuid) ||
        !is_string($name) || !preg_match('/^[A-Za-z0-9@._:\/-]{1,128}$/D',$name) ||
        !is_bool($arg['expected_enabled']))
        throw new RuntimeException('INVALID_REQUEST');
    if (preg_match('/^host\/LAB-DC0[12]\.ad\.example\.test$/iD',$name))
        throw new RuntimeException('PROTECTED_USER');
    // The only exception to guestwlan protection is the exact guest_enabled
    // command, with the exact lowercase identity and live VLAN 30.
    if (strcasecmp($name,'guestwlan')===0 &&
        (!$guestAction || $name!=='guestwlan'))
        throw new RuntimeException('PROTECTED_USER');
    if ($guestAction && $name!=='guestwlan')
        throw new RuntimeException('PROTECTED_USER');

    $model=new User();
    $node=$model->getNodeByReference('users.user.'.$uuid);
    if ($node===null) throw new RuntimeException('USER_NOT_FOUND');
    $liveName=(string)$node->username;
    $oldVlan=trim((string)$node->vlan);
    $oldEnabled=(string)$node->enabled;
    if ($liveName!==$name) throw new RuntimeException('IDENTITY_OR_VLAN_MISMATCH');
    if ($portalAction) {
        if ($oldVlan!=='') throw new RuntimeException('IDENTITY_OR_VLAN_MISMATCH');
    } elseif ($guestAction) {
        if ($oldVlan!=='30') throw new RuntimeException('IDENTITY_OR_VLAN_MISMATCH');
    } elseif (!ctype_digit($oldVlan) || (int)$oldVlan<1 || (int)$oldVlan>4094) {
        throw new RuntimeException('IDENTITY_OR_VLAN_MISMATCH');
    }
    if (!in_array($oldEnabled,['0','1'],true))
        throw new RuntimeException('UNKNOWN_ENABLED_STATE');
    if (($oldEnabled==='1')!==$arg['expected_enabled'])
        throw new RuntimeException('STATE_CHANGED');

    if ($vlanAction) {
        $requested=$arg['vlan'];$expected=$arg['expected_vlan'];
        if (!is_int($requested) || !is_int($expected) ||
            $requested<1 || $requested>4094 || $expected<1 || $expected>4094)
            throw new RuntimeException('INVALID_REQUEST');
        if ((int)$oldVlan!==$expected) throw new RuntimeException('VLAN_CHANGED');
        if ($requested===$expected) throw new RuntimeException('VLAN_ALREADY_REQUESTED');
        $node->vlan->setValue((string)$requested);
    } else {
        if (!is_bool($arg['enabled'])) throw new RuntimeException('INVALID_REQUEST');
        if ($arg['enabled']===$arg['expected_enabled'])
            throw new RuntimeException('STATE_ALREADY_REQUESTED');
        $node->enabled->setValue($arg['enabled']?'1':'0');
    }

    $validation=$model->performValidation();
    if (count($validation)>0) throw new RuntimeException('MODEL_VALIDATION_FAILED');
    $model->serializeToConfig();
    Config::getInstance()->save();
    $result=['ok'=>true,'uuid'=>$uuid,'username'=>$liveName];
    if ($vlanAction) $result['vlan']=$requested;
    else $result['enabled']=$arg['enabled'];
    echo json_encode($result,JSON_THROW_ON_ERROR);
} catch (Throwable $e) {
    $reason=$e->getMessage();
    $known=['INVALID_REQUEST','PROTECTED_USER','USER_NOT_FOUND',
        'IDENTITY_OR_VLAN_MISMATCH','UNKNOWN_ENABLED_STATE','STATE_CHANGED',
        'STATE_ALREADY_REQUESTED','VLAN_CHANGED','VLAN_ALREADY_REQUESTED',
        'MODEL_VALIDATION_FAILED'];
    if (!in_array($reason,$known,true)) $reason='OPNSENSE_SAVE_FAILED';
    fwrite(STDERR,$reason."\n");
    exit(1);
}
