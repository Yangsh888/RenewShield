<?php
declare(strict_types=1);

namespace TypechoPlugin\RenewShield;

if (!defined('__TYPECHO_ROOT_DIR__')) {
    exit;
}

class Seq
{
    public static function evaluate(Context $context, array $settings): ?array
    {
        if (($settings['sequenceProtect'] ?? '0') !== '1' || $context->method !== 'GET') {
            return null;
        }

        $key = self::fingerprint($context);
        $window = (int) ($settings['sequenceWindow'] ?? 600);

        if ($context->isStaticAsset()) {
            State::set('seq:asset:' . $key, time(), $window);
            return null;
        }

        if (!$context->isPageRequest() || $context->isLogin || $context->isComment || $context->isXmlRpc || $context->isUpload) {
            return null;
        }

        $paths = State::get('seq:paths:' . $key, []);
        if (!is_array($paths)) {
            $paths = [];
        }

        $classes = State::get('seq:mix:' . $key, []);
        if (!is_array($classes)) {
            $classes = [];
        }

        $now = time();
        $paths = self::trimTimes($paths, $now - $window);
        $classes = self::trimTimes($classes, $now - $window);

        $pathKey = sha1(strtolower(rtrim($context->path, '/')));
        $paths[$pathKey] = $now;

        $class = $context->pathClass();
        $classes[$class . ':' . $pathKey] = $now;

        State::set('seq:paths:' . $key, $paths, $window);
        State::set('seq:mix:' . $key, $classes, $window);

        $uniquePathCount = count($paths);
        $searchMixCount = self::mixCount($classes);
        $score = 0;
        $reasons = [];

        $pathLimit = (int) ($settings['sequenceUniquePathLimit'] ?? 25);
        if ($uniquePathCount > $pathLimit) {
            $score += 50;
            $reasons[] = 'unique-path';
        }

        $mixLimit = (int) ($settings['sequenceSearchMixLimit'] ?? 6);
        if ($searchMixCount > $mixLimit) {
            $score += 30;
            $reasons[] = 'path-mix';
        }

        $assetSeen = (int) State::get('seq:asset:' . $key, 0);
        if (($settings['sequenceNoAssetBias'] ?? '1') === '1' && $assetSeen <= 0 && $uniquePathCount >= 8) {
            $score += 20;
            $reasons[] = 'assetless';
        }

        if ($score <= 0) {
            return null;
        }

        $challengeScore = (int) ($settings['sequenceChallengeScore'] ?? 70);
        $blockScore = (int) ($settings['sequenceScoreLimit'] ?? 100);
        $policy = (string) ($settings['sequencePolicy'] ?? 'challenge');
        $decision = 'observe';
        if ($score >= $blockScore && $policy === 'block') {
            $decision = 'block';
        } elseif ($score >= $challengeScore) {
            $decision = $policy === 'observe' ? 'observe' : 'challenge';
        }

        $rule = in_array('assetless', $reasons, true) && count($reasons) === 1 ? 'sequence.assetless' : 'sequence.crawl';

        return [
            'decision' => $decision,
            'rule' => $rule,
            'score' => $score,
            'message' => '检测到低速广撒网式访问行为',
            'payload' => [
                'fingerprint' => $key,
                'unique_path_count' => $uniquePathCount,
                'search_mix_count' => $searchMixCount,
                'reason' => implode(',', $reasons),
            ],
        ];
    }

    private static function fingerprint(Context $context): string
    {
        return sha1(implode('|', [
            strtolower($context->ip),
            strtolower($context->ua),
            strtolower((string) ($context->headers['accept'] ?? '')),
            strtolower((string) ($context->headers['accept-language'] ?? '')),
            strtolower((string) ($context->headers['accept-encoding'] ?? '')),
            strtolower((string) ($context->headers['sec-fetch-site'] ?? '')),
        ]));
    }

    private static function trimTimes(array $items, int $min): array
    {
        foreach ($items as $key => $time) {
            if ((int) $time < $min) {
                unset($items[$key]);
            }
        }

        return $items;
    }

    private static function mixCount(array $classes): int
    {
        $groups = [];
        foreach (array_keys($classes) as $key) {
            [$group] = explode(':', $key, 2);
            if (in_array($group, ['search', 'tag', 'category', 'author', 'date', 'page'], true)) {
                $groups[$group] = true;
            }
        }

        return count($groups);
    }
}
