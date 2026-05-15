<?php
declare(strict_types=1);

namespace TypechoPlugin\RenewShield;

use Typecho\Cache;
use Typecho\Common;
use Utils\Helper;
use Utils\Pref;

if (!defined('__TYPECHO_ROOT_DIR__')) {
    exit;
}

class Settings
{
    private const NAME = 'RenewShield';
    private const CACHE_KEY = 'renewshield:settings:v2';

    private static ?array $runtime = null;

    public static function load(): array
    {
        if (is_array(self::$runtime)) {
            return self::$runtime;
        }

        $cache = self::cache();
        if ($cache->enabled()) {
            try {
                $hit = false;
                $cached = $cache->get(self::CACHE_KEY, $hit);
                if ($hit && is_array($cached)) {
                    self::$runtime = self::ensureSignKeyStored($cached, 'load.cache');
                    return self::$runtime;
                }
            } catch (\Throwable $e) {
                self::report('cache.get', $e);
            }
        }

        self::$runtime = self::loadResolved('load.read', 'load.retry', 'load.missing');
        if ($cache->enabled()) {
            try {
                $cache->set(
                    self::CACHE_KEY,
                    self::$runtime,
                    max(60, (int) (self::$runtime['cacheTtl'] ?? 300))
                );
            } catch (\Throwable $e) {
                self::report('cache.set', $e);
            }
        }

        return self::$runtime;
    }

    public static function loadFresh(): array
    {
        return self::loadResolved('fresh.read', 'fresh.retry', 'fresh.missing');
    }

    public static function defaults(): array
    {
        return [
            'enabled' => '1',
            'profile' => 'balanced',
            'cacheTtl' => 300,
            'panelSize' => 10,
            'logKeepDays' => 30,
            'signKey' => '',
            'wafMode' => 'balanced',
            'riskMode' => 'challenge',
            'allowSpiders' => '1',
            'spiderCacheHours' => 24,
            'denyEmptyUa' => '1',
            'blockScriptUa' => '1',
            'writeProtect' => '1',
            'writeWindow' => 60,
            'writeLimit' => 30,
            'writeReplayCheck' => '1',
            'writeReplayWindow' => 120,
            'writeReplayLimit' => 3,
            'writeChallengeMode' => 'challenge',
            'loginIpWindow' => 900,
            'loginIpLimit' => 12,
            'loginSprayCheck' => '1',
            'loginSprayUserLimit' => 6,
            'searchProtect' => '1',
            'searchWindow' => 120,
            'searchLimit' => 20,
            'searchKeywordBurst' => 8,
            'searchMinKeywordLen' => 1,
            'searchMaxKeywordLen' => 64,
            'aiBotPolicy' => 'observe',
            'aiBotAllowlist' => '',
            'aiBotRules' => '',
            'scriptClientPolicy' => 'block',
            'scriptClientAllowlist' => '',
            'browserCheck' => '0',
            'minChrome' => 90,
            'minFirefox' => 90,
            'minEdge' => 90,
            'minSafari' => 13,
            'secFetchCheck' => '0',
            'headerCompleteness' => '0',
            'httpVersionCheck' => '0',
            'blockProxy' => '0',
            'denyBadMethods' => '1',
            'wafEnable' => '1',
            'autoBanHours' => 24,
            'generalWindow' => 60,
            'generalLimit' => 150,
            'loginWindow' => 900,
            'loginLimit' => 5,
            'commentWindow' => 300,
            'commentLimit' => 6,
            'xmlrpcWindow' => 600,
            'xmlrpcLimit' => 10,
            'badLimit' => 8,
            'challengeWait' => 3,
            'trapBanHours' => 72,
            'commentLinks' => 3,
            'commentMinSeconds' => 4,
            'commentRequireChallenge' => '0',
            'uploadDoubleExt' => '1',
            'uploadScan' => '1',
            'uploadMaxKb' => 0,
            'xmlrpcAllowlist' => '',
            'proxyTrusted' => '',
            'ipAllowlist' => "127.0.0.1\n::1",
            'ipDenylist' => '',
            'uaAllowlist' => '',
            'uaDenylist' => '',
            'trapPaths' => implode("\n", [
                '/.env',
                '/.user.ini',
                '/.git/',
                '/.svn/',
                '/phpmyadmin/',
                '/phpmyadmin/index.php',
                '/pma/',
                '/install/',
                '/install.php',
                '/adminer.php',
                '/mysql.php',
                '/composer.json',
                '/composer.lock',
                '/.git/HEAD',
                '/wp-admin/',
                '/wp-login.php',
                '/xmlrpc.php',
                '/vendor/phpunit/',
                '/vendor/autoload.php',
                '/vendor/composer/installed.json',
                '/server-status',
                '/phpinfo.php',
                '/info.php',
                '/install.php.bak',
                '/config.inc.php',
                '/config.inc.php.bak',
                '/config.php.bak',
                '/backup.zip',
                '/backup.sql',
                '/dump.sql',
                '/usr/uploads/*.php',
                '/usr/uploads/*.php5',
                '/usr/uploads/*.pht',
                '/usr/uploads/*.phtml',
                '/usr/uploads/*.phar',
                '/var/Utils/',
                '/var/IXR/',
                '/var/Widget/',
                '/var/Typecho/',
                '/runtime/logs/',
            ]),
            'accessRules' => '',
            'accessHtml' => '<p><strong>当前内容暂未开放</strong></p><p>请使用有权限的账号登录后访问。</p><p>该请求已被访问规则拦截，原页面未继续加载。</p>',
            'accessRedirect' => '',
            'basicAuthEnable' => '0',
            'basicAuthRealm' => 'Protected Area',
            'basicAuthRules' => '',
            'basicAuthUser' => '',
            'basicAuthHash' => '',
            'basicAuthBypassLoggedAdmin' => '1',
            'sequenceProtect' => '0',
            'sequenceWindow' => 600,
            'sequenceScoreLimit' => 100,
            'sequenceChallengeScore' => 70,
            'sequenceUniquePathLimit' => 25,
            'sequenceSearchMixLimit' => 6,
            'sequenceNoAssetBias' => '1',
            'sequencePolicy' => 'challenge',
        ];
    }

    public static function boolKeys(): array
    {
        return [
            'enabled',
            'allowSpiders',
            'denyEmptyUa',
            'blockScriptUa',
            'writeProtect',
            'writeReplayCheck',
            'loginSprayCheck',
            'searchProtect',
            'browserCheck',
            'secFetchCheck',
            'headerCompleteness',
            'httpVersionCheck',
            'blockProxy',
            'denyBadMethods',
            'wafEnable',
            'commentRequireChallenge',
            'uploadDoubleExt',
            'uploadScan',
            'basicAuthEnable',
            'basicAuthBypassLoggedAdmin',
            'sequenceProtect',
            'sequenceNoAssetBias',
        ];
    }

    public static function profiles(): array
    {
        return [
            'conservative' => '保守模式',
            'balanced' => '平衡模式',
            'strict' => '严格模式',
            'custom' => '自定义',
        ];
    }

    public static function tabs(): array
    {
        return ['global', 'request', 'challenge', 'access', 'ops'];
    }

    public static function wafModes(): array
    {
        return [
            'observe' => '仅观察',
            'balanced' => '平衡模式',
            'block' => '直接拦截',
        ];
    }

    public static function riskModes(): array
    {
        return [
            'observe' => '仅观察',
            'challenge' => '基础验证',
            'block' => '直接拦截',
        ];
    }

    public static function store(array $settings): void
    {
        $stored = array_merge(self::defaults(), self::readStored('store.read'));
        self::writeStored(array_merge($stored, $settings), 'store.write');
    }

    public static function storeProfile(array $settings): void
    {
        $stored = array_merge(self::defaults(), self::readStored('store.read'));
        $settings = self::applyProfile(array_merge($stored, $settings));
        self::writeStored($settings, 'store.profile');
    }

    public static function ensureStored(): void
    {
        $settings = array_merge(self::defaults(), self::readStored('ensure.read'));
        self::writeStored($settings, 'ensure.write');
    }

    public static function clear(): void
    {
        Pref::forget(self::$runtime, self::CACHE_KEY, [self::class, 'report']);
    }

    public static function normalize(array $settings): array
    {
        $settings = array_intersect_key($settings, self::defaults());
        $settings = array_merge(self::defaults(), $settings);

        foreach (self::boolKeys() as $key) {
            $settings[$key] = self::bool($settings[$key] ?? '0');
        }

        $settings['profile'] = self::choice((string) ($settings['profile'] ?? 'balanced'), array_keys(self::profiles()), 'balanced');
        $settings['wafMode'] = self::choice((string) ($settings['wafMode'] ?? 'balanced'), array_keys(self::wafModes()), 'balanced');
        $settings['riskMode'] = self::choice((string) ($settings['riskMode'] ?? 'challenge'), array_keys(self::riskModes()), 'challenge');
        $settings['writeChallengeMode'] = self::choice((string) ($settings['writeChallengeMode'] ?? 'challenge'), ['challenge', 'block'], 'challenge');
        $settings['aiBotPolicy'] = self::choice((string) ($settings['aiBotPolicy'] ?? 'observe'), ['observe', 'challenge', 'block', 'allow'], 'observe');
        $settings['scriptClientPolicy'] = self::choice((string) ($settings['scriptClientPolicy'] ?? 'block'), ['observe', 'challenge', 'block'], 'block');
        $settings['sequencePolicy'] = self::choice((string) ($settings['sequencePolicy'] ?? 'challenge'), ['observe', 'challenge', 'block'], 'challenge');

        foreach ([
            'cacheTtl' => [60, 3600, 300],
            'panelSize' => [10, 200, 10],
            'logKeepDays' => [1, 3650, 30],
            'spiderCacheHours' => [1, 168, 24],
            'minChrome' => [0, 999, 90],
            'minFirefox' => [0, 999, 90],
            'minEdge' => [0, 999, 90],
            'minSafari' => [0, 999, 13],
            'autoBanHours' => [1, 720, 24],
            'generalWindow' => [10, 3600, 60],
            'generalLimit' => [5, 10000, 150],
            'loginWindow' => [60, 86400, 900],
            'loginLimit' => [2, 100, 5],
            'loginIpWindow' => [60, 86400, 900],
            'loginIpLimit' => [2, 500, 12],
            'loginSprayUserLimit' => [2, 100, 6],
            'writeWindow' => [10, 3600, 60],
            'writeLimit' => [1, 10000, 30],
            'writeReplayWindow' => [30, 86400, 120],
            'writeReplayLimit' => [1, 1000, 3],
            'commentWindow' => [30, 86400, 300],
            'commentLimit' => [1, 100, 6],
            'xmlrpcWindow' => [30, 86400, 600],
            'xmlrpcLimit' => [1, 500, 10],
            'searchWindow' => [30, 86400, 120],
            'searchLimit' => [1, 1000, 20],
            'searchKeywordBurst' => [1, 200, 8],
            'searchMinKeywordLen' => [1, 64, 1],
            'searchMaxKeywordLen' => [1, 255, 64],
            'badLimit' => [1, 100, 8],
            'challengeWait' => [0, 30, 3],
            'trapBanHours' => [1, 720, 72],
            'commentLinks' => [0, 50, 3],
            'commentMinSeconds' => [0, 60, 4],
            'uploadMaxKb' => [0, 102400, 0],
            'sequenceWindow' => [60, 86400, 600],
            'sequenceScoreLimit' => [50, 500, 100],
            'sequenceChallengeScore' => [20, 500, 70],
            'sequenceUniquePathLimit' => [5, 500, 25],
            'sequenceSearchMixLimit' => [2, 100, 6],
        ] as $key => [$min, $max, $default]) {
            $settings[$key] = self::int($settings[$key] ?? $default, $min, $max, $default);
        }

        $settings['signKey'] = self::token($settings['signKey'] ?? '');

        $settings['ipAllowlist'] = self::ipLines($settings['ipAllowlist'] ?? '');
        $settings['ipDenylist'] = self::ipLines($settings['ipDenylist'] ?? '');
        $settings['xmlrpcAllowlist'] = self::ipLines($settings['xmlrpcAllowlist'] ?? '');
        $settings['proxyTrusted'] = self::ipLines($settings['proxyTrusted'] ?? '');
        $settings['uaAllowlist'] = self::textLines($settings['uaAllowlist'] ?? '', 255, 200);
        $settings['uaDenylist'] = self::textLines($settings['uaDenylist'] ?? '', 255, 200);
        $settings['aiBotAllowlist'] = self::textLines($settings['aiBotAllowlist'] ?? '', 255, 200);
        $settings['aiBotRules'] = self::textLines($settings['aiBotRules'] ?? '', 255, 200);
        $settings['scriptClientAllowlist'] = self::textLines($settings['scriptClientAllowlist'] ?? '', 255, 200);
        $settings['trapPaths'] = self::pathLines($settings['trapPaths'] ?? '');
        $settings['accessRules'] = self::ruleLines($settings['accessRules'] ?? '');
        $settings['accessHtml'] = self::html($settings['accessHtml'] ?? '', 12000);
        $settings['accessRedirect'] = self::urlOrRelative($settings['accessRedirect'] ?? '', 1024);
        $settings['basicAuthRealm'] = self::plainText($settings['basicAuthRealm'] ?? '', 120, 'Protected Area');
        $settings['basicAuthRules'] = self::pathLines($settings['basicAuthRules'] ?? '');
        $settings['basicAuthUser'] = self::plainText($settings['basicAuthUser'] ?? '', 80, '');
        $settings['basicAuthHash'] = Text::cut(trim((string) ($settings['basicAuthHash'] ?? '')), 255);
        $settings['profile'] = self::profileTag($settings);

        return $settings;
    }

    public static function cache(): Cache
    {
        return Cache::getInstance();
    }

    public static function panelUrl(): string
    {
        return Helper::url(self::NAME . '/Panel.php');
    }

    public static function panelQueryUrl(array $query = []): string
    {
        $clean = [];
        foreach ($query as $key => $value) {
            $value = trim((string) $value);
            if ($value !== '') {
                $clean[$key] = $value;
            }
        }

        if ($clean === []) {
            return self::panelUrl();
        }

        $url = self::panelUrl();
        $separator = str_contains($url, '?') ? '&' : '?';
        return $url . $separator . http_build_query($clean);
    }

    public static function assetUrl(string $path): string
    {
        return Common::url(self::NAME . '/' . ltrim($path, '/'), (string) Helper::options()->pluginUrl);
    }

    public static function actionUrl(string $do = '', bool $secure = false): string
    {
        $path = '/action/renew-shield';
        if ($do !== '') {
            $path .= '?do=' . rawurlencode($do);
        }

        if ($secure) {
            return \Widget\Security::alloc()->getIndex($path);
        }

        return Common::url($path, (string) Helper::options()->index);
    }

    public static function siteUrl(): string
    {
        return (string) Helper::options()->siteUrl;
    }

    public static function profileDefaults(string $profile): array
    {
        return match ($profile) {
            'conservative' => [
                'wafMode' => 'observe',
                'riskMode' => 'challenge',
                'browserCheck' => '0',
                'secFetchCheck' => '0',
                'headerCompleteness' => '0',
                'httpVersionCheck' => '0',
                'blockProxy' => '0',
                'writeProtect' => '1',
                'writeLimit' => 40,
                'searchProtect' => '1',
                'searchLimit' => 30,
                'loginIpLimit' => 16,
                'loginSprayCheck' => '1',
                'aiBotPolicy' => 'observe',
                'scriptClientPolicy' => 'challenge',
                'sequenceProtect' => '0',
                'generalWindow' => 60,
                'generalLimit' => 180,
                'loginLimit' => 6,
                'commentLimit' => 8,
                'challengeWait' => 2,
                'badLimit' => 10,
                'commentRequireChallenge' => '0',
            ],
            'strict' => [
                'wafMode' => 'block',
                'riskMode' => 'block',
                'browserCheck' => '1',
                'secFetchCheck' => '1',
                'headerCompleteness' => '1',
                'httpVersionCheck' => '0',
                'blockProxy' => '1',
                'writeProtect' => '1',
                'writeLimit' => 20,
                'searchProtect' => '1',
                'searchLimit' => 12,
                'loginIpLimit' => 8,
                'loginSprayCheck' => '1',
                'aiBotPolicy' => 'challenge',
                'scriptClientPolicy' => 'block',
                'sequenceProtect' => '0',
                'generalWindow' => 60,
                'generalLimit' => 90,
                'loginLimit' => 4,
                'commentLimit' => 5,
                'challengeWait' => 4,
                'badLimit' => 6,
                'commentRequireChallenge' => '1',
            ],
            'balanced' => [
                'wafMode' => 'balanced',
                'riskMode' => 'challenge',
                'browserCheck' => '0',
                'secFetchCheck' => '0',
                'headerCompleteness' => '0',
                'httpVersionCheck' => '0',
                'blockProxy' => '0',
                'writeProtect' => '1',
                'writeLimit' => 30,
                'searchProtect' => '1',
                'searchLimit' => 20,
                'loginIpLimit' => 12,
                'loginSprayCheck' => '1',
                'aiBotPolicy' => 'observe',
                'scriptClientPolicy' => 'block',
                'sequenceProtect' => '0',
                'generalWindow' => 60,
                'generalLimit' => 150,
                'loginLimit' => 5,
                'commentLimit' => 6,
                'challengeWait' => 3,
                'badLimit' => 8,
                'commentRequireChallenge' => '0',
            ],
        };
    }

    public static function rootPath(string $relative = ''): string
    {
        $root = rtrim(__TYPECHO_ROOT_DIR__, '\\/');
        $relative = ltrim(str_replace(['/', '\\'], DIRECTORY_SEPARATOR, trim($relative)), DIRECTORY_SEPARATOR);
        return $relative === '' ? $root : $root . DIRECTORY_SEPARATOR . $relative;
    }

    public static function report(string $scope, \Throwable $e): void
    {
        try {
            Log::write('system', 'error', 'observe', 'settings.' . $scope, 0, $e->getMessage(), [
                'class' => get_class($e),
            ]);
        } catch (\Throwable) {
        }
    }

    private static function readStored(string $scope): array
    {
        try {
            $options = Helper::options()->plugin(self::NAME);
            return is_object($options) && method_exists($options, 'toArray')
                ? (array) $options->toArray()
                : [];
        } catch (\Throwable $e) {
            self::report($scope, $e);
            return [];
        }
    }

    private static function loadResolved(string $readScope, string $retryScope, string $repairScope): array
    {
        $raw = self::readStored($readScope);
        if (empty($raw)) {
            self::ensureStored();
            $raw = self::readStored($retryScope);
        }

        return self::ensureSignKeyStored($raw, $repairScope);
    }

    private static function ensureSignKeyStored(array $settings, string $scope): array
    {
        $settings = self::normalize($settings);
        $stored = self::normalize(self::readStored($scope . '.read'));
        if (($stored['signKey'] ?? '') !== '') {
            $settings['signKey'] = (string) $stored['signKey'];
            return $settings;
        }

        if (($settings['signKey'] ?? '') === '') {
            $settings['signKey'] = self::generateSignKey();
        }

        if (!self::persist($settings, $scope . '.store')) {
            return $settings;
        }

        $stored = self::normalize(self::readStored($scope . '.verify'));
        if (($stored['signKey'] ?? '') !== '') {
            return $stored;
        }

        self::report($scope . '.verify', new \RuntimeException('签名密钥修复后仍未写入插件配置'));
        return $settings;
    }

    private static function writeStored(array $settings, string $scope): void
    {
        $settings = self::normalize($settings);
        if (($settings['signKey'] ?? '') === '') {
            $settings['signKey'] = self::generateSignKey();
        }

        self::persist($settings, $scope);
    }

    private static function persist(array $settings, string $scope): bool
    {
        try {
            Helper::configPlugin(self::NAME, $settings);
        } catch (\Throwable $e) {
            self::report($scope, $e);
            return false;
        }

        self::clear();
        return true;
    }

    private static function generateSignKey(): string
    {
        return bin2hex(random_bytes(24));
    }

    private static function applyProfile(array $settings): array
    {
        $profile = self::choice((string) ($settings['profile'] ?? 'balanced'), array_keys(self::profiles()), 'balanced');
        if ($profile === 'custom') {
            return $settings;
        }

        foreach (self::profileDefaults($profile) as $key => $value) {
            $settings[$key] = $value;
        }

        $settings['profile'] = $profile;
        return $settings;
    }

    private static function profileTag(array $settings): string
    {
        foreach (['conservative', 'balanced', 'strict'] as $profile) {
            $matched = true;
            foreach (self::profileDefaults($profile) as $key => $value) {
                if ((string) ($settings[$key] ?? '') !== (string) $value) {
                    $matched = false;
                    break;
                }
            }

            if ($matched) {
                return $profile;
            }
        }

        return 'custom';
    }

    private static function bool(mixed $value): string
    {
        return in_array((string) $value, ['1', 'true', 'on', 'yes'], true) ? '1' : '0';
    }

    private static function choice(string $value, array $allowed, string $default): string
    {
        return in_array($value, $allowed, true) ? $value : $default;
    }

    private static function int(mixed $value, int $min, int $max, int $default): int
    {
        $value = filter_var($value, FILTER_VALIDATE_INT);
        if ($value === false) {
            return $default;
        }

        return max($min, min($max, (int) $value));
    }

    private static function token(mixed $value): string
    {
        $value = preg_replace('/[^a-f0-9]/i', '', (string) $value) ?? '';
        return Text::cut(strtolower($value), 96);
    }

    private static function textLines(mixed $value, int $maxLen, int $maxLines): string
    {
        return implode("\n", Text::lines((string) $value, $maxLen, $maxLines));
    }

    private static function plainText(mixed $value, int $max, string $default = ''): string
    {
        $value = preg_replace('/[\x00-\x1F\x7F]/u', '', trim((string) $value));
        if (!is_string($value) || $value === '') {
            return $default;
        }

        return Text::cut($value, $max);
    }

    private static function ipLines(mixed $value): string
    {
        $clean = [];
        foreach (Text::lines((string) $value, 64, 200) as $line) {
            $line = trim($line);
            if ($line === '') {
                continue;
            }
            if (filter_var($line, FILTER_VALIDATE_IP) === false
                && !preg_match('/^[0-9a-f:\.]+\/\d{1,3}$/i', $line)) {
                continue;
            }
            $clean[] = strtolower($line);
        }

        return implode("\n", array_values(array_unique($clean)));
    }

    private static function pathLines(mixed $value): string
    {
        $clean = [];
        foreach (Text::lines((string) $value, 255, 200) as $line) {
            $line = self::normalizePath($line);
            if ($line === '/' || str_contains($line, '..')) {
                continue;
            }
            $clean[] = Text::cut($line, 255);
        }

        return implode("\n", array_values(array_unique($clean)));
    }

    public static function normalizePath(string $path): string
    {
        $path = '/' . ltrim(trim($path), '/');
        return preg_replace('#/+#', '/', $path) ?? '/';
    }

    private static function ruleLines(mixed $value): string
    {
        return implode("\n", Text::lines((string) $value, 255, 200));
    }

    private static function html(mixed $value, int $max): string
    {
        $value = trim((string) $value);
        if ($value === '') {
            return '';
        }

        $value = preg_replace(
            [
                '#<script\b[^>]*>.*?</script>#is',
                '#<iframe\b[^>]*>.*?</iframe>#is',
                '/\s+on[a-z0-9_-]+\s*=\s*(".*?"|\'.*?\'|[^\s>]+)/iu',
                '/javascript\s*:/iu',
            ],
            ['', '', '', ''],
            $value
        );

        if (!is_string($value)) {
            return '';
        }

        return Text::cut($value, $max);
    }

    private static function urlOrRelative(mixed $value, int $max): string
    {
        $value = Text::cut(trim((string) $value), $max);
        if ($value === '') {
            return '';
        }

        if (str_starts_with($value, '/')) {
            return preg_replace('#/+#', '/', $value) ?? '/';
        }

        if (preg_match('#^https?://#i', $value)) {
            return self::absoluteHttpUrl($value);
        }

        return '';
    }

    private static function absoluteHttpUrl(string $value): string
    {
        $target = Common::parseUrl($value);
        if ($target === []) {
            return '';
        }

        $scheme = strtolower((string) ($target['scheme'] ?? ''));
        $targetHost = strtolower((string) ($target['host'] ?? ''));
        if ($targetHost === '' || !in_array($scheme, ['http', 'https'], true)) {
            return '';
        }

        $targetPort = (int) ($target['port'] ?? 0);
        $path = '/' . ltrim((string) ($target['path'] ?? '/'), '/');
        $path = preg_replace('#/+#', '/', $path) ?? '/';
        $query = isset($target['query']) ? '?' . (string) $target['query'] : '';
        $fragment = isset($target['fragment']) ? '#' . (string) $target['fragment'] : '';
        $port = $targetPort > 0 ? ':' . $targetPort : '';

        return $scheme . '://' . $targetHost . $port . $path . $query . $fragment;
    }
}
