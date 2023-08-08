
# Features

- Make Encryption of any string by console command
- Make Decryption of any string by console command
- Encrypted string from .env but Decrypted string will pass in config/database.php to establish database connection. So that credentials are not readable with bare eyes


## Acknowledgements
This code has been created below environment. If some thing occured due to version issue please adjust the code a little bit. 
 - [php": "^8.1.0](https://www.php.net/releases/8.0/en.php)
 - [laravel/framework": "^9.19](https://laravel.com/docs/9.x/installation)
# Encryption Decryption
Once you are inside your Laravel project folder, execute the following command to create the EncryptDecryptService.php file in the app/Services directory:
```bash
touch app/Services/EncryptDecryptService.php
```
Now copy below code to the following file

```php
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
```
Now to test, Lets encrypt and decrypt a string. But before that lets create a console command to do these operations

```
php artisan make:command EncryptDecryptCommand
```
Put below code on the file *app/Console/Commands/EncryptDecryptCommand.php*
```
<?php
// app/Console/Commands/EncryptDecryptCommand.php

namespace App\Console\Commands;

use App\Services\EncryptDecryptService;
use Illuminate\Console\Command;
use Illuminate\Support\Facades\Hash;
use App\Models\User;

class EncryptDecryptCommand extends Command
{
    protected $signature = 'encrypt:decrypt';
    protected $description = 'Encrypt or decrypt a given string';

    public function handle()
    {
        $this->info('Authentication required to proceed.');
        $email = $this->ask('Enter admin email:');
        $password = $this->secret('Enter admin password:');

        // Perform admin authentication
        $user = User::where('email', $email)->first();

        if (!$user || !Hash::check($password, $user->password)) {
            $this->error('Authentication failed. Invalid email or password.');
            return;
        }

        $this->info('Authentication successful.');
        $encryptDecryptService = new EncryptDecryptService();

        $option = $this->choice('Choose an option:', ['Encrypt', 'Decrypt']);
        $input = $this->ask('Enter the string to ' . strtolower($option) . ':');

        if ($option === 'Encrypt') {
            $output = $encryptDecryptService->encryption($input);
        } else {
            $output = $encryptDecryptService->decryption($input);
        }

        $this->info('Output: ' . $output);
    }
}
```
Now you can run the command from the terminal
```
php artisan encrypt:decrypt
```
The command will prompt you to enter your admin credentials
```
Enter admin email:
Enter admin password:
```
If the authentication is successful, the command will display
```
Authentication successful.
```
Choose an option
```
Choose an option:
  [0] Encrypt
  [1] Decrypt
```
Based on your selection, you will be prompted to enter the string to encrypt or decrypt
```
Enter the string to encrypt/decrypt:
```
The command will display the encrypted or decrypted output
```
'Output: ' . $output
```
So the test works fine. Now lets put this in *config/database.php* and put below code at top of the file.

```php
try {
    $DbUserName = (new \App\Services\EncryptDecryptService())->decryption(env('DB_USERNAME'));
    $DbUserPassword = (new \App\Services\EncryptDecryptService())->decryption(env('DB_PASSWORD'));
} catch (\Exception $e) {
    dd(__FILE__ . ' | ' . $e->getMessage());
}
```
Need to tweak little bit in 
```
 'connections' => [
        'mysql' => [
         
            'database' => env('DB_DATABASE', 'forge'),
            //'username' => env('DB_USERNAME', 'forge'),
            // 'password' => env('DB_PASSWORD', ''),
            'username' => $DbUserName,
            'password' => $DbUserPassword,
        ],
]
```
Now if you set encrypted value for *DB_USERNAME* & *DB_PASSWORD* in *.env* file this will be work.