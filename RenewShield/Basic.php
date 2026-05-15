<?php
declare(strict_types=1);

namespace TypechoPlugin\RenewShield;

use Typecho\Response;

if (!defined('__TYPECHO_ROOT_DIR__')) {
    exit;
}

class Basic
{
    public static function enforce(Context $context, array $settings): bool
    {
        if (($settings['basicAuthEnable'] ?? '0') !== '1') {
            return false;
        }

        if (!self::matchPath($context->path, (string) ($settings['basicAuthRules'] ?? ''))) {
            return false;
        }

        if (
            ($settings['basicAuthBypassLoggedAdmin'] ?? '1') === '1'
            && \Widget\User::alloc()->pass('administrator', true)
        ) {
            return false;
        }

        $expectUser = trim((string) ($settings['basicAuthUser'] ?? ''));
        $hash = trim((string) ($settings['basicAuthHash'] ?? ''));
        if ($expectUser === '' || $hash === '') {
            Log::write('auth', 'auth', 'block', 'basic.auth.required', 90, 'Basic Auth 已启用，但配置不完整');
            self::unauthorized((string) ($settings['basicAuthRealm'] ?? 'Protected Area'));
        }

        [$user, $password] = self::credentials();
        if ($user === null || $password === null) {
            Log::write('auth', 'auth', 'block', 'basic.auth.required', 65, '命中受保护路径，需提供 Basic Auth 凭证', [
                'path_hash' => sha1(strtolower(rtrim($context->path, '/'))),
            ]);
            self::unauthorized((string) ($settings['basicAuthRealm'] ?? 'Protected Area'));
        }

        if (!hash_equals($expectUser, $user) || !password_verify($password, $hash)) {
            Log::write('auth', 'auth', 'block', 'basic.auth.fail', 85, 'Basic Auth 验证失败', [
                'path_hash' => sha1(strtolower(rtrim($context->path, '/'))),
            ]);
            self::unauthorized((string) ($settings['basicAuthRealm'] ?? 'Protected Area'));
        }

        Log::write('auth', 'auth', 'allow', 'basic.auth.pass', 0, 'Basic Auth 验证通过');
        return false;
    }

    private static function credentials(): array
    {
        $user = $_SERVER['PHP_AUTH_USER'] ?? null;
        $password = $_SERVER['PHP_AUTH_PW'] ?? null;
        if (is_string($user) && is_string($password)) {
            return [$user, $password];
        }

        $header = (string) ($_SERVER['HTTP_AUTHORIZATION'] ?? $_SERVER['REDIRECT_HTTP_AUTHORIZATION'] ?? '');
        if ($header === '' || stripos($header, 'Basic ') !== 0) {
            return [null, null];
        }

        $decoded = base64_decode(substr($header, 6), true);
        if (!is_string($decoded) || !str_contains($decoded, ':')) {
            return [null, null];
        }

        [$user, $password] = explode(':', $decoded, 2);
        return [$user, $password];
    }

    private static function matchPath(string $path, string $rules): bool
    {
        $path = Settings::normalizePath($path);
        foreach (Text::lines($rules, 255, 200) as $rule) {
            $rule = Settings::normalizePath($rule);
            if ($rule === '' || $rule === '/') {
                continue;
            }

            if (str_contains($rule, '*')) {
                $pattern = '#^' . str_replace('\*', '.*', preg_quote(rtrim($rule, '/'), '#')) . '/?$#i';
                if (preg_match($pattern, rtrim($path, '/')) === 1) {
                    return true;
                }
                continue;
            }

            if (rtrim($path, '/') === rtrim($rule, '/')) {
                return true;
            }
        }

        return false;
    }

    private static function unauthorized(string $realm): never
    {
        $realm = trim($realm) !== '' ? trim($realm) : 'Protected Area';
        $response = Response::getInstance();
        $response->setStatus(401)
            ->setHeader('WWW-Authenticate', 'Basic realm="' . addslashes($realm) . '", charset="UTF-8"')
            ->setHeader('Cache-Control', 'no-store, no-cache, must-revalidate')
            ->setHeader('Pragma', 'no-cache')
            ->setContentType('text/html', 'UTF-8')
            ->sendHeaders();

        echo '<!DOCTYPE html><html lang="zh-CN"><head><meta charset="UTF-8"><title>需要验证</title></head><body><p>当前路径需要通过 HTTP Basic Auth 验证后访问。</p></body></html>';
        exit;
    }
}
