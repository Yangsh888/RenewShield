<?php
declare(strict_types=1);

namespace TypechoPlugin\RenewShield;

use Typecho\Common;
use Typecho\Request;

if (!defined('__TYPECHO_ROOT_DIR__')) {
    exit;
}

class Abuse
{
    private const WRITE_METHODS = ['POST', 'PUT', 'PATCH', 'DELETE'];
    private const BODY_HASH_BYTES = 32768;
    private const NOISE_KEYS = [
        'token',
        '_',
        'csrf',
        'security',
        'do',
        'referer',
        'renewshield_ctx',
        'renewshield_hp',
    ];

    public static function write(Context $context, array $settings): ?array
    {
        if (($settings['writeProtect'] ?? '1') !== '1' || !in_array($context->method, self::WRITE_METHODS, true)) {
            return null;
        }

        $window = (int) ($settings['writeWindow'] ?? 60);
        $limit = (int) ($settings['writeLimit'] ?? 30);
        $pathHash = sha1($context->routeScope() . '|' . strtolower(rtrim($context->path, '/')));
        $count = State::hit('write:rate:' . sha1($context->ip) . ':' . $pathHash, $window);
        if ($count > $limit) {
            return [
                'decision' => (string) ($settings['writeChallengeMode'] ?? 'challenge'),
                'rule' => 'write.rate.limit',
                'score' => 70,
                'message' => '写请求频率过高，请稍后再试',
                'payload' => [
                    'count' => $count,
                    'limit' => $limit,
                    'window' => $window,
                    'path_hash' => $pathHash,
                    'reason' => 'write-rate',
                ],
            ];
        }

        if (($settings['writeReplayCheck'] ?? '1') !== '1') {
            return null;
        }

        $bodyHash = self::bodyHash($context);
        if ($bodyHash === '') {
            return null;
        }

        $replayWindow = (int) ($settings['writeReplayWindow'] ?? 120);
        $replayLimit = (int) ($settings['writeReplayLimit'] ?? 3);
        $replayCount = State::hit(
            'write:replay:' . sha1($context->ip) . ':' . sha1($context->method . '|' . $pathHash . '|' . $bodyHash),
            $replayWindow
        );
        if ($replayCount > $replayLimit) {
            return [
                'decision' => (string) ($settings['writeChallengeMode'] ?? 'challenge'),
                'rule' => 'write.replay',
                'score' => 80,
                'message' => '检测到重复写请求，请确认后再试',
                'payload' => [
                    'count' => $replayCount,
                    'limit' => $replayLimit,
                    'window' => $replayWindow,
                    'path_hash' => $pathHash,
                    'body_hash' => $bodyHash,
                    'reason' => 'write-replay',
                ],
            ];
        }

        return null;
    }

    public static function login(Context $context, array $settings): ?array
    {
        if (!$context->isLogin || $context->method !== 'POST') {
            return null;
        }

        $window = (int) ($settings['loginIpWindow'] ?? 900);
        $limit = (int) ($settings['loginIpLimit'] ?? 12);
        $ipCount = (int) State::get(self::loginIpKey($context->ip), 0);
        if ($ipCount >= $limit) {
            return [
                'decision' => 'block',
                'rule' => 'login.ip.limit',
                'score' => 88,
                'message' => '当前来源的登录失败次数过多，请稍后再试',
                'payload' => [
                    'count' => $ipCount,
                    'limit' => $limit,
                    'window' => $window,
                    'ip' => $context->ip,
                ],
            ];
        }

        if (($settings['loginSprayCheck'] ?? '1') !== '1') {
            return null;
        }

        $users = State::get(self::loginSprayKey($context->ip), []);
        $userCount = is_array($users) ? count($users) : 0;
        $userLimit = (int) ($settings['loginSprayUserLimit'] ?? 6);
        if ($userCount >= $userLimit && $ipCount >= max(3, $userLimit)) {
            return [
                'decision' => 'block',
                'rule' => 'login.spray',
                'score' => 92,
                'message' => '检测到疑似撞库或喷洒行为，当前来源已被阻断',
                'payload' => [
                    'attempted_users' => $userCount,
                    'limit' => $userLimit,
                    'window' => $window,
                    'ip' => $context->ip,
                ],
            ];
        }

        return null;
    }

    public static function recordLoginFail(Context $context, string $name, array $settings): void
    {
        $window = (int) ($settings['loginIpWindow'] ?? 900);
        State::hit(self::loginIpKey($context->ip), $window);

        if (($settings['loginSprayCheck'] ?? '1') !== '1') {
            return;
        }

        $name = strtolower(trim($name));
        if ($name === '') {
            return;
        }

        $users = State::get(self::loginSprayKey($context->ip), []);
        if (!is_array($users)) {
            $users = [];
        }

        $users[$name] = time();
        State::set(self::loginSprayKey($context->ip), $users, $window);
    }

    public static function recordLoginSuccess(Context $context): void
    {
        State::delete(self::loginIpKey($context->ip));
        State::delete(self::loginSprayKey($context->ip));
    }

    public static function search(Context $context, array $settings): ?array
    {
        if (($settings['searchProtect'] ?? '1') !== '1' || !$context->isSearch) {
            return null;
        }

        $keywords = self::searchKeywords();
        if ($keywords === '') {
            return null;
        }

        $window = (int) ($settings['searchWindow'] ?? 120);
        $limit = (int) ($settings['searchLimit'] ?? 20);
        $count = State::hit('search:rate:' . sha1($context->ip), $window);
        if ($count > $limit) {
            return [
                'decision' => 'challenge',
                'rule' => 'search.rate.limit',
                'score' => 70,
                'message' => '搜索请求过于频繁，请稍后再试',
                'payload' => [
                    'count' => $count,
                    'limit' => $limit,
                    'window' => $window,
                    'keyword_sample' => Text::cut($keywords, 64),
                ],
            ];
        }

        $minLen = (int) ($settings['searchMinKeywordLen'] ?? 1);
        $maxLen = (int) ($settings['searchMaxKeywordLen'] ?? 64);
        $length = function_exists('mb_strlen') ? mb_strlen($keywords, 'UTF-8') : strlen($keywords);
        if ($length < $minLen || $length > $maxLen) {
            return [
                'decision' => 'observe',
                'rule' => 'search.keyword.invalid',
                'score' => 20,
                'message' => '搜索关键词长度异常',
                'payload' => [
                    'keyword_sample' => Text::cut($keywords, 64),
                    'reason' => 'keyword-length',
                ],
            ];
        }

        $setKey = 'search:kwset:' . sha1($context->ip);
        $keywordsSet = State::get($setKey, []);
        if (!is_array($keywordsSet)) {
            $keywordsSet = [];
        }

        $normalized = strtolower($keywords);
        $keywordsSet[$normalized] = time();
        State::set($setKey, $keywordsSet, $window);
        $burstLimit = (int) ($settings['searchKeywordBurst'] ?? 8);
        if (count($keywordsSet) > $burstLimit) {
            return [
                'decision' => 'challenge',
                'rule' => 'search.keyword.burst',
                'score' => 72,
                'message' => '短时间内搜索关键词变化过多，请稍后再试',
                'payload' => [
                    'count' => count($keywordsSet),
                    'limit' => $burstLimit,
                    'window' => $window,
                    'keyword_sample' => Text::cut($keywords, 64),
                ],
            ];
        }

        return null;
    }

    public static function searchKeywords(): string
    {
        $keywords = Request::getInstance()->get('keywords', '');
        $keywords = is_scalar($keywords) ? (string) $keywords : '';
        return trim(Common::filterSearchQuery($keywords));
    }

    private static function bodyHash(Context $context): string
    {
        $contentLength = (int) ($context->headers['content-length'] ?? 0);
        if ($contentLength > self::BODY_HASH_BYTES) {
            return '';
        }

        $contentType = strtolower((string) ($context->headers['content-type'] ?? ''));
        $payload = null;

        if (str_contains($contentType, 'application/json')) {
            $payload = Request::getInstance()->getJsonBody();
        } elseif ($_POST !== []) {
            $payload = $_POST;
        } else {
            $raw = Text::cut($context->body, self::BODY_HASH_BYTES);
            if ($raw === '') {
                return '';
            }

            $parsed = [];
            parse_str($raw, $parsed);
            $payload = $parsed !== [] ? $parsed : ['@raw' => $raw];
        }

        $normalized = self::normalizePayload($payload);
        if ($normalized === [] || $normalized === ['@raw' => '']) {
            return '';
        }

        $json = json_encode($normalized, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
        if (!is_string($json) || $json === '') {
            return '';
        }

        return sha1($json);
    }

    private static function normalizePayload(mixed $payload): mixed
    {
        if (is_array($payload)) {
            $normalized = [];
            foreach ($payload as $key => $value) {
                $name = is_string($key) ? strtolower(trim($key)) : (string) $key;
                if ($name !== '' && in_array($name, self::NOISE_KEYS, true)) {
                    continue;
                }

                $normalized[$name] = self::normalizePayload($value);
            }

            ksort($normalized);
            return $normalized;
        }

        if (is_bool($payload)) {
            return $payload ? '1' : '0';
        }

        if (is_numeric($payload)) {
            return (string) $payload;
        }

        if (is_scalar($payload)) {
            return trim((string) $payload);
        }

        return '';
    }

    private static function loginIpKey(string $ip): string
    {
        return 'login:ip:fail:' . sha1(strtolower(trim($ip)));
    }

    private static function loginSprayKey(string $ip): string
    {
        return 'login:spray:users:' . sha1(strtolower(trim($ip)));
    }
}
