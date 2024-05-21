<?php
/**
 * Project: esia
 * File: SignerCryptoPro.php
 * Created by: mn.rumynin
 * Date: 22.09.2021
 * Time: 22:38
 */

namespace Esia\Signer;

use Esia\Signer\Exceptions\CryptoProMessageException;
use Esia\Signer\Exceptions\CryptoProExecException;
use Esia\Signer\Exceptions\CryptoProSignException;
use Esia\Signer\Exceptions\CryptoProResultException;

class SignerCryptoPro implements SignerInterface
{

    /**
     * Path to CryptoPro
     */
    private string $cryptoPath;
    /**
     * Thumbprint (Hash) of personal cert, using to choose for sign
     */
    private $thumbprint;
    /**
     * Pin for access to personal cert
     */
    private string $pin;
    /**
     * Path to temporary files
     */
    private string $tmpPath;
    /**
     * TODO: Keep temporary files
     */
    private bool $keepTemp;

    public function __construct(string $cryptoPath, string $tmpPath, string $thumbprint, string $pin)
    {
        $this->cryptoPath = $cryptoPath;
        $this->tmpPath = $tmpPath;
        $this->thumbprint = $thumbprint;
        $this->pin = $pin;
        $this->keepTemp = false;
    }

    /**
     * Generate random unique string
     */
    protected function getRandomString(): string
    {
        return md5(uniqid(mt_rand(), true));
    }

    /**
     * Sign the given message using CryptoPro.
     *
     * @param string $message The message to sign.
     * @return string The base64 encoded signature.
     * @throws CryptoProMessageException If the message cannot be written to a file.
     * @throws CryptoProExecException If there is an error executing the cryptcp command.
     * @throws CryptoProResultException If the sign log process cannot be written to a file.
     * @throws CryptoProSignException If the signature cannot be read from a file.
     */
    public function sign(string $message): string
    {
        // Generate a random unique string for the message file
        $messageFile = $this->getRandomString();

        // Write the message to a file
        $messagePath = $this->tmpPath . "/" . $messageFile . '.msg';
        if (!file_put_contents($messagePath, $message)) {
            throw new CryptoProMessageException('Cannot write message to ' . $messagePath);
        }

        // Construct the cryptcp command
        $cmd = '%s/cryptcp -signf -der -strict -cert -detached -dir "%s" -dn root -thumbprint "%s" -pin "%s" "%s"';
        $cmd = sprintf($cmd,
            $this->cryptoPath,
            $this->tmpPath,
            $this->thumbprint,
            $this->pin,
            $messagePath
        );

        // Execute the cryptcp command and get the output
        $output = null;
        $retv = null;
        if (!exec($cmd, $output, $retv)) {
            throw new CryptoProExecException('Error executing ' . $cmd);
        }

        // Write the sign log process to a file
        $resultPath = $this->tmpPath . "/" . $messageFile . ".res";
        $listing = $cmd . "\n" . implode("\n", $output);
        if (!file_put_contents($resultPath, $listing)) {
            throw new CryptoProResultException('Cannot write sign log process to ' . $resultPath);
        }

        // Read the signature from a file
        $signaturePath = $this->tmpPath . "/" . $messageFile . '.msg.sgn';
        $signature = file_get_contents($signaturePath);
        if (!$signature) {
            throw new CryptoProSignException('Cannot read signature from ' . $signaturePath);
        }

        // Base64 encode the signature
        $encoded = base64_encode($signature);

        // Remove temporary files if not kept
        if (!$this->keepTemp) {
            $tempFiles = [
                $messagePath,
                $resultPath,
                $signaturePath,
            ];
            foreach ($tempFiles as $file) {
                unlink($file);
            }
        }

        // Replace special characters in the base64 encoded signature
        return str_replace(array('+', '/', '='), array('-', '_', ''), $encoded);
    }
}