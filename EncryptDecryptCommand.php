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
