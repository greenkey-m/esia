<?php
/**
 * Project: esia2.rkn.gov.ru
 * File: CryptoSign.php
 * Created by: mn.rumynin
 * Date: 22.09.2021
 * Time: 22:38
 */

namespace App\Module;

use Esia\Signer\Exceptions\SignFailException;
use Esia\Signer\SignerInterface;

class SignerCryptoPro implements SignerInterface
{

    /**
     * Path to CryptoPro
     *
     * @var string
     */
    private $cryptoPath;
    /**
     * Thumbprint (Hash) of personal cert, using to choose for sing
     *
     * @var string
     */
    private $thumbprint;
    /**
     * Pin for access to personal cert
     *
     * @var string
     */
    private $pin;
    /**
     * @var string
     */
    private $tmpPath;

    public function __construct(string $cryptoPath, string $tmpPath, string $thumbprint, string $pin)
    {
        $this->cryptoPath = $cryptoPath;
        $this->tmpPath = $tmpPath;
        $this->thumbprint = $thumbprint;
        $this->pin = $pin;
    }

    /**
     * Generate random unique string
     */
    protected function getRandomString(): string
    {
        return md5(uniqid(mt_rand(), true));
    }

    /**
     * @inheritDoc
     */
    public function sign(string $message): string
    {
        // TODO: Implement sign() method.
        $messageFile = $this->getRandomString();
        file_put_contents($this->tmpPath . "/" . $messageFile, $message);
        //$cmd = $this->cryptoPath . '/cryptcp -signf -der -strict -cert -detached -dn root -thumbprint "'.$this->thumbprint.'" -pin "1234567890" "message"';
        $cmd = '%s/cryptcp -signf -der -strict -cert -detached -dir "%s" -dn root -thumbprint "%s" -pin "%s" "%s"';
        $cmd = sprintf($cmd,
            $this->cryptoPath,
            $this->tmpPath,
            $this->thumbprint,
            $this->pin,
            $this->tmpPath . "/" . $messageFile
        );
        $output = null;
        $retv = null;
        $result = exec($cmd, $output, $retv);
        $signature = file_get_contents($this->tmpPath . "/" . $messageFile . '.sgn');
        $encoded = base64_encode($signature);
        unlink($this->tmpPath . "/" . $messageFile);
        unlink($this->tmpPath . "/" . $messageFile . ".sgn");
        return str_replace(array('+', '/', '='), array('-', '_', ''), $encoded);
    }
}