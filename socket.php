<?php
//licensed under GNU GPL.
//See the LICENSE file

class HerculesAPI
{

    private $core = 1;
    private $packets = array();
    private $maxkeysize = 33;
    private $maxpacketsize = 2048;
    private $defaultparse = null;

    /**
     * HerculesAPI::WFIFOB()
     * 
     * @param mixed $data
     * @return
     */
    public static function WFIFOB($data)
    {
        return pack('c', $data);
    }

    /**
     * HerculesAPI::WFIFOW()
     * 
     * @param mixed $data
     * @return
     */
    public  static function WFIFOW($data)
    {
        return pack('v', $data);
    }

    /**
     * HerculesAPI::WFIFOL()
     * 
     * @param mixed $data
     * @return
     */
    public static function WFIFOL($data)
    {
        return pack('V', $data);
    }

    /**
     * HerculesAPI::WFIFOP()
     * 
     * @param mixed $data
     * @param mixed $size
     * @return
     */
    public static function WFIFOP($data, $size)
    {
        return pack("a{$size}", $data);
    }

    /**
     * HerculesAPI::WFIFOQ()
     * 
     * @param mixed $data
     * @return
     */
    public static function WFIFOQ($data)
    {
        return pack('VV', $data & 0xffffffff, ($data >> 32) & 0xffffffff);
    }

    /**
     * HerculesAPI::RFIFOB()
     * 
     * @param mixed $data
     * @param mixed $pos
     * @return
     */
    public static function RFIFOB($data, $pos)
    {
        $result = unpack("@{$pos}/c", $data);
        return $result[1];
    }

    /**
     * HerculesAPI::RFIFOW()
     * 
     * @param mixed $data
     * @param mixed $pos
     * @return
     */
    public static function RFIFOW($data, $pos)
    {
        $result = unpack("@{$pos}/v", $data);
        return $result[1];
    }

    /**
     * HerculesAPI::RFIFOL()
     * 
     * @param mixed $data
     * @param mixed $pos
     * @return
     */
    public static function RFIFOL($data, $pos)
    {
        $result = unpack("@{$pos}/V", $data);
        return $result[1];
    }

    /**
     * HerculesAPI::RFIFOP()
     * 
     * @param mixed $data
     * @param mixed $pos
     * @param mixed $size
     * @return
     */
    public static function RFIFOP($data, $pos, $size)
    {
        $result = unpack("@{$pos}/a{$size}", $data);
        return $result[1];
    }

    /**
     * HerculesAPI::RFIFOQ()
     * 
     * @param mixed $data
     * @param mixed $pos
     * @return
     */
    public static function RFIFOQ($data, $pos)
    {
        $result = unpack('Vlow/Vhigh', $data);
        return $result['low'] | $result['high'] << 32;
    }

    /**
     * HerculesAPI::RFIFOREST()
     * 
     * @param mixed $data
     * @return
     */
    public static function RFIFOREST($data)
    {
        return mb_strlen($data);
    }

    /**
     * HerculesAPI::make_connection()
     * 
     * @param mixed $serverip
     * @param mixed $serverport
     * @return
     */
    public function make_connection($serverip, $serverport)
    {

        $fd = socket_create(AF_INET, SOCK_STREAM, getprotobyname('tcp'));

        if ($fd == false) {

            printf("make_connection: socket creation fail '%s' ", socket_strerror(socket_last_error
                ($fd)));
            return false;
        }

        $connect = socket_connect($fd, $serverip, $serverport);

        if ($connect == false) {

            printf("make_connection: socket connection fail '%s' ", socket_strerror(socket_last_error
                ($connect)));
            socket_close($fd);
            return false;
        }

        socket_set_nonblock($fd);

        return $fd;
    }

    /**
     * HerculesAPI::do_parse()
     * 
     * @param mixed $fd
     * @return
     */
    public function do_parse($fd)
    {
        while ($this->core != 0) {
            $data = socket_read($fd, $this->maxpacketsize);
            if ($data == false || mb_strlen($data) == 0)
                continue;
            $this->parse_from_server($data, $fd);
        }
        socket_close($fd);
    }

    /**
     * HerculesAPI::parse_from_server()
     * 
     * @param mixed $data
     * @param mixed $socket
     * @return
     */
    public function parse_from_server($data, $socket)
    {
        $packet = $this->RFIFOW($data, 0);
        if (isset($this->packets[$packet])) {
            
            $this->core = $this->packets[$packet]($data, $socket, $this);
            
        } elseif (is_null($this->defaultparse) == false) {
            
            $parse_function = $this->defaultparse;
            $this->core = $parse_function($data, $socket, $this);
            
        } else {
            
            echo "Error Packet 0x" . dechex($packet) . " not found";
            $this->core = 0;
            
        }
    }

    /**
     * HerculesAPI::send_packet()
     * 
     * @param mixed $fd
     * @param mixed $packetid
     * @param mixed $apikey
     * @param mixed $data
     * @return
     */
    public function send_packet($fd, $packetid, $apikey, $data)
    {

        $content = $this->WFIFOW($packetid);

        if ($apikey != null) {
            if (strlen($apikey) > $this->maxkeysize - 1) {
                printf("Max Key size is %d characters", $this->maxkeysize - 1);
                $this->core = 0;
            } else {
                $content .= $this->WFIFOP($apikey, 32 + 1);
            }
        }

        $content .= $data;

        return socket_write($fd, $content);
    }

    /**
     * HerculesAPI::set_core()
     * 
     * @param mixed $set
     * @return
     */
    public function set_core($set)
    {

        $this->core = ($set == on) ? 1 : 0;

    }

    /**
     * HerculesAPI::get_core()
     * 
     * @return
     */
    public function get_core()
    {

        return $this->core;

    }

    /**
     * HerculesAPI::add_packet()
     * 
     * @param mixed $function
     * @param mixed $packetid
     * @param mixed $islike
     * @return
     */
    public function add_packet($function, $packetid, $islike = null)
    {

        if (is_null($islike) == true)
            $this->packets[$packetid] = $function;
        else
            $this->packets[$packetid] = $this->packets[$islike];

        var_dump($this->packets);
        return true;

    }

    /**
     * HerculesAPI::set_maxpacketsize()
     * 
     * @param mixed $size
     * @return
     */
    public function set_maxpacketsize($size)
    {

        if (is_nan($size) == false)
            return false;

        $this->maxpacketsize = $size;
        return true;
    }

    /**
     * HerculesAPI::get_maxpacketsize()
     * 
     * @return
     */
    public function get_maxpacketsize()
    {

        return $this->maxpacketsize;

    }

    /**
     * HerculesAPI::set_maxkeysize()
     * 
     * @param mixed $keysize
     * @return
     */
    public function set_maxkeysize($keysize)
    {

        if (is_nan($keysize) == false)
            return false;

        $this->maxkeysize = $keysize + 1;

        return true;

    }

    /**
     * HerculesAPI::get_maxkeysize()
     * 
     * @return
     */
    public function get_maxkeysize()
    {

        return $this->maxkeysize;

    }

    /**
     * HerculesAPI::set_defaultparse()
     * 
     * @param mixed $function
     * @return
     */
    public function set_defaultparse($function)
    {

        if (function_exists($function) == false) {

            printf("You Should chosse a vaild function for default parse");
            exit();

        }

        $this->defaultparse = $function;
        return true;
    }
}
?>