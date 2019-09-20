<?php

namespace josecarlosphp\easyservice;

require_once 'vendor/josecarlosphp/functions/src/internet.php';
require_once 'vendor/josecarlosphp/functions/src/arrays.php';
require_once 'vendor/josecarlosphp/functions/src/files.php';

require_once '_inc/classes/MySession.class.php';
include_once '_inc/classes/MyServiceResponse.class.php';

class App
{
    /**
     * @var boolean
     */
    private $debug;
    /**
     * @var string
     */
    private $dirSess = '_sess';
    /**
     * @var string
     */
    private $dirLog = '_log';
    /**
     * @var string
     */
    private $dirDebug = '_debug';
    /**
     * @var boolean
     */
    private $useArray = false;
    /**
     * @var MySession
     */
    private $session;

    public function __construct($debug=false, $props=array())
    {
        $this->debug($debug);

        foreach($props as $key=>$val)
        {
            if(property_exists($this, $key) && $key != 'session')
            {
                $this->$key = $val;
            }
        }

        $arr = get_object_vars($this);
        foreach($arr as $key=>$val)
        {
            if(mb_substr($key, 0, 3) == 'dir')
            {
                $this->$key = ponerBarra($val);
                if(!is_dir($this->$key) && makeDir($this->$key))
                {
                    file_put_contents($this->$key.'.htaccess', 'Deny from all');
                }
            }
        }
    }

    public static function getDefaultConfig()
    {
        return array(
            'tokenlifetime'=>90,
            'tokenlenght'=>64,
            );
    }

    public static function getConfig($q)
    {
        $config = self::getDefaultConfig();

        $filename = 'q/'.LimpiarData($q).'/config.yml';
        if(is_file($filename))
        {
            $aux = self::yamlRead($filename);
            foreach($aux as $key=>$val)
            {
                if(array_key_exists($key, $config))
                {
                    $config[$key] = $val;
                }
            }
        }

        return $config;
    }

    public static function getAllHeaders()
    {
        if(!function_exists('getallheaders'))
        {
            function getallheaders()
            {
                $arh = array();
                $rx_http = '/\AHTTP_/';
                foreach($_SERVER as $key => $val)
                {
                    if(preg_match($rx_http, $key))
                    {
                        $arh_key = preg_replace($rx_http, '', $key);
                        // do some nasty string manipulations to restore the original letter case
                        // this should work in most cases
                        $rx_matches = explode('_', $arh_key);
                        if(count($rx_matches) > 0 and strlen($arh_key) > 2 )
                        {
                            foreach($rx_matches as $ak_key => $ak_val)
                            {
                                $rx_matches[$ak_key] = ucfirst(mb_strtolower($ak_val));
                            }
                            $arh_key = implode('-', $rx_matches);
                        }
                        $arh[$arh_key] = $val;
                    }
                }

                return $arh;
            }
        }

        return getallheaders();
    }

    public function run()
    {
        global $app; //Para que esté disponible, por ejemplo para $app->debugging()

        if(empty($app))
        {
            $app = $this; //Por si la variable se ha declarado con otro nombre
        }

        $this->logging('$_REQUEST = '.var_export($_REQUEST, true));

        $q = isset($_GET['q']) ? LimpiarData($_GET['q']) : '';
        $action = isset($_GET['action']) ? mb_strtolower(LimpiarData($_GET['action'])) : '';
        $params = $_REQUEST; //$_POST

        $headers = self::getAllHeaders();
        $token = isset($headers['Ocp-Apim-Subscription-Key']) ? $headers['Ocp-Apim-Subscription-Key'] : (isset($params['token']) ? LimpiarData($params['token']) : '');

        $this->debugging('get', $_GET);
        $this->debugging('post', $_POST);
        $this->debugging('headers', $headers);
        $this->debugging('body', file_get_contents('php://input'));

        if($q && $action)
        {
            if(is_dir('q/'.$q))
            {
                if(is_file('q/'.$q.'/'.$action.'.php'))
                {
                    $filename = 'q/'.$q.'/_inc/functions.inc.php';
                    if(is_file($filename))
                    {
                        include $filename;
                    }

                    $config = self::getConfig($q);

                    \MySession::Init(ponerBarra(getcwd().'/'.$this->dirSess).$q.'/', $config['tokenlifetime'], $config['tokenlifetime'] == 0 ? 0 : 1, 1, $config['tokenlenght']);

                    switch($action)
                    {
                        case 'open':
                            $this->session = new \MySession();
                            $token = $this->session->GetId();
                            break;
                        case 'close':
                            if(!\MySession::Destroy($token))
                            {
                                $this->doResult(\MyServiceResponse::STATUS_ERROR, MySession::Exists($token) ? 'Can not destroy session' : 'Bad token');
                            }
                            break;
                        default:
                            $this->session = new \MySession();
                            if($this->session->Load($token) === false)
                            {
                                $this->doResult(\MyServiceResponse::STATUS_ERROR, 'Bad token', 401);
                            }
                            elseif($this->session->Get('sessid') != $token)
                            {
                                $this->doResult(\MyServiceResponse::STATUS_ERROR, 'Mismatch token', 401);
                            }
                            break;
                    }

                    include 'q/'.$q.'/'.$action.'.php';

                    switch($action)
                    {
                        case 'open':
                            $this->session->Set($token, 'sessid');
                            $app->doResult(\MyServiceResponse::STATUS_OK, $token);
                            break;
                        case 'close':
                            $app->doResult(\MyServiceResponse::STATUS_OK, null);
                            break;
                        default:
                            $app->doResult(\MyServiceResponse::STATUS_ERROR, 'Unexpected error');
                            break;
                    }
                }
                else
                {
                    $this->doResult(\MyServiceResponse::STATUS_ERROR, 'Unknown action: '.$action, 400);
                }
            }

            http_response_code(404);
            exit;
        }

        http_response_code(503);
        exit;
    }

    protected function doResult($status, $content, $code=200)
    {
        if($this->useArray)
        {
            if(is_string($content))
            {
                $content = array($content);
            }
            elseif(is_null($content))
            {
                $content = array();
            }
        }

        $this->logging('[Result: '.$status.'] '.var_export($content, true), 'general');
        http_response_code($code);
        header('Content-Type: application/json');
        echo json_encode(array(
            'status'=>$status,
            'content'=>$content,
        ));
        exit;
    }

    public function debug($debug=null)
    {
        if(!is_null($debug))
        {
            $this->debug = $debug ? true : false;
        }

        return $this->debug;
    }

    public function debugging($q, $var)
    {
        if($this->debug)
        {
            file_put_contents($this->dirDebug.$q, var_export($var, true));
        }
    }

    public function logging($str, $q='general')
    {
        $dir = $this->dirLog.date('Y/m/');
        if(makeDir($dir))
        {
            if(($fp = fopen($dir.date('Y-m-d').'.'.$q.'.log', 'a')))
            {
                $r = fwrite($fp, sprintf('[%s] - %s%s', date('Y-m-d H:i:s'), $str, "\n"));
                fclose($fp);

                return $r > 0;
            }
        }

        return false;
    }

    public function SessionSet($val, $key0, $key1=null, $key2=null, $key3=null, $key4=null, $key5=null)
    {
        return $this->session->Set($val, $key0, $key1, $key2, $key3, $key4, $key5);
    }

    public function SessionGet($key0, $key1=null, $key2=null, $key3=null, $key4=null, $key5=null)
    {
        return $this->session->Get($key0, $key1, $key2, $key3, $key4, $key5);
    }

    public static function yamlRead($filename)
    {
        return \Spyc::YAMLLoad($filename);
    }

    public static function yamlWrite($filename, $data)
    {
        return file_put_contents($filename, \Spyc::YAMLDump($data, 4, 0, true));
    }
}
