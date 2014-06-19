<?php
ini_set('display_errors', 'on');
error_reporting(E_ALL);
require_once "socket.php"; // include hercules api class

$api = new HerculesAPI; // initialized hercules api class
$fd = $api->make_connection('31.193.131.100', 6900); // connection to login server

// Set defs
$api->set_maxkeysize(52); // Change max API key length from 32 to 52
$api->set_maxpacketsize(4096); // Change max income packet size from 2048 bytes to 4096 bytes


function parse_fromlogin($data, $socket, $api)
{

    $packet_id = $api->RFIFOW($data, 0);

    switch ($packet_id) {

        case 0x0069:

            $servertypes = array(
                0 => "Normal",
                1 => "Under Maintenance",
                2 => "+18",
                3 => "Pay To Play",
                4 => "Free To Play",
                );

            $serversamount = ($api->RFIFOW($data, 2) - 47) / 32;
            printf("Account ID %d \n", $api->RFIFOL($data, 8));
            printf("Sex: %s \n", ($api->RFIFOB($data, 46) == 0) ? "Female" : "Male");
            $i = 0;
            while ($i < $serversamount) {
                printf("Character Server IP: %s \n", long2ip(unpack('L', pack('N', $api->RFIFOL
                    ($data, 47 + $i * 32)))[1]));
                printf("Character Server Port: %d \n", $api->RFIFOW($data, 47 + $i * 32 + 4));
                printf("Character Server Name: %s \n", $api->RFIFOP($data, 47 + $i * 32 + 6, 20));
                printf("Character Server Users: %d \n", $api->RFIFOW($data, 47 + $i * 32 + 26));
                printf("Character Server Type: %s \n", $servertypes[$api->RFIFOW($data, 47 + $i *
                    32 + 28)]);
                printf("Character Server Status: %s \n", ($api->RFIFOW($data, 47 + $i * 32 + 30) ==
                    0) ? "Old" : "New");
                ++$i;
            }
            return 0;

        break;

        case 0x83e:

            $error = array(
                1 => "Server Closed",
                8 => "Server still recognizes your last login",
                );
            printf("Script recv error while login : %s \n", $error[$api->RFIFOB($data, 2)]);
            return 0;

        break;

        default:
        
            printf("unknow packet 0x%s stop parsing and close connection", dechex($packet_id));
            
        break;

    }

}

function login_fail($data, $socket, $api)
{
    $error = array(
        0 => "Unregistered ID.",
        1 => "Incorrect Password.",
        2 => "Account Expired.",
        3 => "Rejected from server.",
        4 => "Blocked by GM.",
        5 => "Not latest game EXE.",
        6 => "Banned.",
        7 => "Server Over-population.",
        8 => "Account limit from company",
        9 => "Ban by DBA",
        10 => "Email not confirmed",
        11 => "Ban by GM",
        12 => "Working in DB",
        13 => "Self Lock",
        14 => "Not Permitted Group",
        15 => "Not Permitted Group",
        99 => "Account gone.",
        100 => "Login info remains.",
        101 => "Hacking investigation.",
        102 => "Bug investigation.",
        103 => "Deleting char.",
        104 => "Deleting spouse char.",
        );

    printf("Script recv error while login : %s \n", $error[$api->RFIFOW($data, 2)]);
    return 0;
}


$api->set_defaultparse("parse_fromlogin");
$api->add_packet("login_fail", 0x83e);
$api->add_packet(null, 0x6a, 0x83e);

// Start make packet content
$data = $api->WFIFOL(20); // Fill First Part add a 4 byte long type data
$data .= $api->WFIFOP('hemagx', 24); // Fill 2nd add 24 bytes long characters 23 for username long and 1 free byte
$data .= $api->WFIFOP('it\'s a secret :3', 24); // Fill 3rd add 24 long characters 23 for password long and 1 free byte
$data .= $api->WFIFOB(1); // Client type ? unknow thing just give 1 byte for it

/*
* Sending the data
* @param the seasion that we want to send the packet to it
* @param the packet id
* @param the api key can be NULL if you don't send api key (Note: this one add 33 more bytes to the packet and this one filled after the packet id)
* @param the data variable
*/
$api->send_packet($fd, 0x0064, null, $data);


$api->do_parse($fd); // make script start parse incoming packet

?>