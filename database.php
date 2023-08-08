<?php

use Illuminate\Support\Str;

try {
    $DbUserName = (new \App\Services\EncryptDecryptService())->decryption(env('DB_USERNAME'));
    $DbUserPassword = (new \App\Services\EncryptDecryptService())->decryption(env('DB_PASSWORD'));
} catch (\Exception $e) {
    dd(__FILE__ . ' | ' . $e->getMessage());
}

return [

    'connections' => [

        'mysql' => [
 
            'database' => env('DB_DATABASE', 'forge'),
            //'username' => env('DB_USERNAME', 'forge'),
            // 'password' => env('DB_PASSWORD', ''),
            'username' => $DbUserName,
            'password' => $DbUserPassword
        
        ],

    ],
];
