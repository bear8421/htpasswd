<?php

if (!function_exists('generateHtpasswdPassword')) {
    function generateHtpasswdPassword($plainTextPassword)
    {
        $uuid = sprintf(
            '%04x%04x-%04x-%04x-%04x-%04x%04x%04x',
            mt_rand(0, 0xffff), // 32 bits for "time_low"
            mt_rand(0, 0xffff), // 16 bits for "time_mid"
            mt_rand(0, 0xffff), // 16 bits for "time_hi_and_version",

            // four most significant bits holds version number 4
            mt_rand(0, 0x0fff) | 0x4000, // 16 bits, 8 bits for "clk_seq_hi_res",

            // 8 bits for "clk_seq_low",

            // two most significant bits holds zero and one for variant DCE1.1
            mt_rand(0, 0x3fff) | 0x8000, // 48 bits for "node"
            mt_rand(0, 0xffff),
            mt_rand(0, 0xffff),
            mt_rand(0, 0xffff)
        );
        // Tạo salt ngẫu nhiên cho bcrypt (2y) hoặc MD5 ($1$)
        $cost = 12;
        $salt = substr(sha1(date('YmdHisu') . $uuid), 0, 22);

        // Mã hóa mật khẩu với bcrypt
        $hashedPassword = crypt($plainTextPassword, '$2y$' . $cost . '$' . $salt . '$');

        // Kiểm tra nếu hệ thống hỗ trợ bcrypt
        if (strlen($hashedPassword) < 60) {
            // Nếu không hỗ trợ bcrypt, fallback to MD5
            $hashedPassword = crypt($plainTextPassword, '$1$' . $salt . '$');
        }

        return $hashedPassword;
    }
}
