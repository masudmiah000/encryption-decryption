<?php

// app/Services/EncryptDecryptService.php

namespace App\Services;

use Illuminate\Support\Str;

/**
 * Class EncryptDecryptService
 *
 * A service class to handle AES-256 encryption and decryption of sensitive data.
 * The encryption key is read from an external INI file.
 *
 * @package App\Services
 */
class EncryptDecryptService
{
    private string $key;

    /**
     * EncryptDecryptService constructor.
     *
     * Initializes the service and retrieves the encryption key from the INI file.
     *
     * @throws \Exception If the encryption key is not found in the INI file.
     */
    public function __construct()
    {
        $this->key = $this->getKeyFromIniFile();
    }

    /**
     * Encrypts the given value using AES-256 encryption.
     *
     * @param string $value The value to be encrypted.
     * @return string The base64-encoded encrypted value.
     * @throws \Exception If encryption fails or the encryption key is invalid.
     */
    public function encryption(string $value): string
    {
        /*
        What is the IV size for AES 256?
        Algorithm   | 	Key size (bytes) |	IV size (bytes)
        AES-256	    |   32	             |  16
        */
        $iv = Str::random();
        dd($iv);
        $encryptedValue = openssl_encrypt($value, 'AES-256-CBC', $this->key, OPENSSL_RAW_DATA, $iv);

        if ($encryptedValue === false) {
            throw new \Exception(__METHOD__ . ' : Encryption failed.');
        }

        return base64_encode($iv . $encryptedValue);
    }

    /**
     * Decrypts the given encrypted value using AES-256 decryption.
     *
     * @param string $encryptedValue The base64-encoded encrypted value.
     * @return string The decrypted value.
     * @throws \Exception If decryption fails or the encryption key is invalid.
     */
    public function decryption(string $encryptedValue): string
    {
        $data = base64_decode($encryptedValue);
        $iv = substr($data, 0, 16);
        if (strlen($iv) != 16) {
            throw new \Exception(__METHOD__ . ' : IV size is not 16 bytes.');
        }
        $cipherText = substr($data, 16);
        $decryptedValue = openssl_decrypt($cipherText, 'AES-256-CBC', $this->key, OPENSSL_RAW_DATA, $iv);

        if ($decryptedValue === false) {
            throw new \Exception(__METHOD__ . ' : Decryption failed.');
        }

        return $decryptedValue;
    }

    /**
     * Gets the encryption key from the INI file.
     *
     * @return string The encryption key.
     * @throws \Exception If the encryption key is not found in the INI file.
     */
    private function getKeyFromIniFile(): string
    {
        /*
        - MyProject
            |- app
            |  |- Services
            |     |- EncryptDecryptService.php
            |- public
            |  |- index.php
        - secrets.ini
        */
        $iniFileName = 'EncryptionDecryptionConfig.ini';
        $iniFile = __DIR__ . '/../../../' . $iniFileName; // Replace with the actual path to your INI file.
        $config = parse_ini_file($iniFile, true);

        if (isset($config['key'])) {
            return (string)$config['key'];
        }

        throw new \Exception(__METHOD__ . ' : Encryption key not found in the INI file.');
    }
}
