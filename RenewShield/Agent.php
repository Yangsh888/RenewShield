<?php
declare(strict_types=1);

namespace TypechoPlugin\RenewShield;

if (!defined('__TYPECHO_ROOT_DIR__')) {
    exit;
}

class Agent
{
    public static function detectAi(Context $context, array $settings): ?array
    {
        $ua = trim($context->ua);
        if ($ua === '' || self::matchList($ua, (string) ($settings['aiBotAllowlist'] ?? ''))) {
            return null;
        }

        foreach (self::aiBots() as $name => $bot) {
            if (preg_match($bot['pattern'], $ua) !== 1) {
                continue;
            }

            return [
                'name' => $name,
                'label' => $bot['label'],
                'rule' => $bot['rule'],
                'decision' => self::policyFor($name, $settings),
                'message' => $bot['label'] . ' 已被识别为 AI 爬虫',
            ];
        }

        return null;
    }

    public static function detectScript(Context $context, array $settings): ?array
    {
        $ua = trim($context->ua);
        if ($ua === '' || self::matchList($ua, (string) ($settings['scriptClientAllowlist'] ?? ''))) {
            return null;
        }

        $tool = self::scriptTool($ua, (string) ($settings['uaDenylist'] ?? ''));
        if ($tool === '') {
            return null;
        }

        return [
            'tool' => $tool,
            'rule' => 'agent.script.client',
            'decision' => self::choice((string) ($settings['scriptClientPolicy'] ?? 'block'), ['observe', 'challenge', 'block'], 'block'),
            'message' => '当前 User-Agent 已被识别为自动化工具：' . $tool,
        ];
    }

    private static function policyFor(string $name, array $settings): string
    {
        $rules = self::ruleMap((string) ($settings['aiBotRules'] ?? ''));
        if (isset($rules[$name])) {
            return $rules[$name];
        }

        return self::choice((string) ($settings['aiBotPolicy'] ?? 'observe'), ['observe', 'challenge', 'block', 'allow'], 'observe');
    }

    private static function choice(string $value, array $allowed, string $default): string
    {
        return in_array($value, $allowed, true) ? $value : $default;
    }

    private static function ruleMap(string $rules): array
    {
        $map = [];
        foreach (Text::lines($rules, 255, 200) as $line) {
            if (!preg_match('/^\s*([a-z0-9._-]+)\s*[:=]\s*(allow|observe|challenge|block)\s*$/i', $line, $matches)) {
                continue;
            }

            $map[strtolower($matches[1])] = strtolower($matches[2]);
        }

        return $map;
    }

    private static function matchList(string $ua, string $rules): bool
    {
        foreach (Text::lines($rules, 255, 200) as $rule) {
            if ($rule !== '' && stripos($ua, $rule) !== false) {
                return true;
            }
        }

        return false;
    }

    private static function scriptTool(string $ua, string $denyList): string
    {
        foreach (Text::lines($denyList, 255, 200) as $rule) {
            if ($rule !== '' && stripos($ua, $rule) !== false) {
                return $rule;
            }
        }

        foreach ([
            'curl' => '/\bcurl\b/i',
            'wget' => '/\bwget\b/i',
            'python-requests' => '/python-requests|python-urllib|aiohttp/i',
            'go-http-client' => '/go-http-client/i',
            'java' => '/java\/|okhttp|apache-httpclient/i',
            'node' => '/node-fetch|axios|got\b/i',
            'php' => '/guzzlehttp|symfony-http-client/i',
            'postman' => '/postmanruntime|insomnia/i',
            'powershell' => '/powershell/i',
        ] as $label => $pattern) {
            if (preg_match($pattern, $ua) === 1) {
                return $label;
            }
        }

        return '';
    }

    private static function aiBots(): array
    {
        return [
            'gptbot' => ['label' => 'GPTBot', 'rule' => 'agent.ai.gptbot', 'pattern' => '/\bgptbot\b/i'],
            'chatgpt-user' => ['label' => 'ChatGPT-User', 'rule' => 'agent.ai.gptbot', 'pattern' => '/\bchatgpt-user\b/i'],
            'claudebot' => ['label' => 'ClaudeBot', 'rule' => 'agent.ai.claudebot', 'pattern' => '/\bclaudebot\b|\bclaude-web\b/i'],
            'perplexity' => ['label' => 'PerplexityBot', 'rule' => 'agent.ai.perplexity', 'pattern' => '/\bperplexitybot\b/i'],
            'bytespider' => ['label' => 'ByteSpider', 'rule' => 'agent.ai.bytespider', 'pattern' => '/\bbytespider\b|\bdoubaobot\b/i'],
            'qwen' => ['label' => 'QwenBot', 'rule' => 'agent.ai.qwen', 'pattern' => '/\bqwenbot\b|\bqwen\b/i'],
            'amazonbot' => ['label' => 'Amazonbot', 'rule' => 'agent.ai.amazonbot', 'pattern' => '/\bamazonbot\b/i'],
            'ccbot' => ['label' => 'CCBot', 'rule' => 'agent.ai.ccbot', 'pattern' => '/\bccbot\b/i'],
        ];
    }
}
