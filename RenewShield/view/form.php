<?php
declare(strict_types=1);

use TypechoPlugin\RenewShield\Text;

$profiles = \TypechoPlugin\RenewShield\Settings::profiles();
$riskModes = \TypechoPlugin\RenewShield\Settings::riskModes();
$wafModes = \TypechoPlugin\RenewShield\Settings::wafModes();
$accessSummary = \TypechoPlugin\RenewShield\Access::summary($settings);
?>
<form id="renewshield-main-form" method="post" action="<?php echo Text::e($saveUrl); ?>">
    <input type="hidden" name="tab" value="<?php echo Text::e($currentTab); ?>">
    <input type="hidden" name="apply_profile" value="0" id="renewshield-apply-profile">

    <div class="tr-panel-pane<?php echo $currentTab === 'global' ? ' is-active' : ''; ?>" data-tab="global">
        <div class="shield-card">
            <div class="shield-card-header">
                <h3 class="shield-card-title">运行概况</h3>
                <p class="shield-card-desc">设置插件启用状态、预设方案与整体处理策略。</p>
            </div>
            <div class="shield-list">
                <div class="shield-list-item">
                    <div class="shield-list-item-meta">
                        <h4 class="shield-list-item-title">全局开关</h4>
                        <p class="shield-list-item-desc">关闭后停止执行防护规则，已记录的日志与状态数据将保留。</p>
                    </div>
                    <div class="shield-list-item-control">
                        <label class="shield-switch">
                            <input type="checkbox" name="enabled" value="1"<?php echo $settings['enabled'] === '1' ? ' checked' : ''; ?>>
                            <span class="shield-slider"></span>
                        </label>
                    </div>
                </div>
                <div class="shield-block-item">
                    <div class="shield-matrix">
                        <label class="shield-field">
                            <span>预设方案</span>
                            <select name="profile" class="shield-input">
                                <?php foreach ($profiles as $value => $label): ?>
                                    <option value="<?php echo Text::e($value); ?>"<?php echo $settings['profile'] === $value ? ' selected' : ''; ?>><?php echo Text::e($label); ?></option>
                                <?php endforeach; ?>
                            </select>
                        </label>
                        <label class="shield-field">
                            <span>风险处理策略</span>
                            <select name="riskMode" class="shield-input">
                                <?php foreach ($riskModes as $value => $label): ?>
                                    <option value="<?php echo Text::e($value); ?>"<?php echo $settings['riskMode'] === $value ? ' selected' : ''; ?>><?php echo Text::e($label); ?></option>
                                <?php endforeach; ?>
                            </select>
                        </label>
                        <label class="shield-field">
                            <span>WAF 处理策略</span>
                            <select name="wafMode" class="shield-input">
                                <?php foreach ($wafModes as $value => $label): ?>
                                    <option value="<?php echo Text::e($value); ?>"<?php echo $settings['wafMode'] === $value ? ' selected' : ''; ?>><?php echo Text::e($label); ?></option>
                                <?php endforeach; ?>
                            </select>
                        </label>
                    </div>
                    <div class="shield-note-grid">
                        <article class="shield-note">
                            <strong>保守模式</strong>
                            <p>优先保证正常访问，并采用较温和的处理方式。</p>
                        </article>
                        <article class="shield-note">
                            <strong>平衡模式</strong>
                            <p>在访问体验与基础防护之间保持均衡。</p>
                        </article>
                        <article class="shield-note">
                            <strong>严格模式</strong>
                            <p>提高风险处理强度，适合防护要求较高的站点。</p>
                        </article>
                    </div>
                    <div class="shield-profile-bar">
                        <div class="shield-profile-copy">
                            <strong>预设方案</strong>
                            <p>应用后将按当前选中的预设更新相关策略；如需保留手动修改，请使用页面底部的“保存当前配置”。</p>
                        </div>
                        <button type="button" class="btn" data-shield-apply-profile="1">使用当前预设并保存</button>
                    </div>
                </div>
            </div>
        </div>

        <div class="shield-card">
            <div class="shield-card-header">
                <h3 class="shield-card-title">面板与存储</h3>
                <p class="shield-card-desc">设置插件配置缓存、面板分页与日志保留策略，不影响防护判定结果。</p>
            </div>
            <div class="shield-list">
                <div class="shield-block-item">
                    <div class="shield-matrix">
                        <label class="shield-field">
                            <span>配置缓存秒数</span>
                            <input type="number" name="cacheTtl" min="30" max="3600" value="<?php echo (int) $settings['cacheTtl']; ?>" class="shield-input">
                        </label>
                        <label class="shield-field">
                            <span>日志每页数量</span>
                            <input type="number" name="panelSize" min="10" max="200" value="<?php echo (int) $settings['panelSize']; ?>" class="shield-input">
                        </label>
                        <label class="shield-field">
                            <span>日志保留天数</span>
                            <input type="number" name="logKeepDays" min="1" max="365" value="<?php echo (int) $settings['logKeepDays']; ?>" class="shield-input">
                        </label>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <div class="tr-panel-pane<?php echo $currentTab === 'request' ? ' is-active' : ''; ?>" data-tab="request">
        <div class="shield-card">
            <div class="shield-card-header">
                <h3 class="shield-card-title">基础请求防护</h3>
                <p class="shield-card-desc">配置脚本访问识别、空 UA 处理、搜索引擎放行与基础 WAF 等通用防护项。</p>
            </div>
            <div class="shield-list">
                <?php foreach ([
                    ['allowSpiders', '搜索引擎放行', '对已支持的 Google、Bing、百度爬虫完成双向验证后放行。'],
                    ['denyEmptyUa', '拦截空 UA', '拦截未携带 User-Agent 的请求。'],
                    ['blockScriptUa', '拦截脚本 UA', '识别并处理常见脚本工具的 User-Agent 特征。'],
                    ['denyBadMethods', '拦截异常方法', '拦截非常规或异常的 HTTP 请求方法。'],
                    ['wafEnable', '启用基础 WAF', '识别注入、路径穿越、协议异常与常见探测路径等风险特征。'],
                ] as [$key, $title, $desc]): ?>
                    <div class="shield-list-item">
                        <div class="shield-list-item-meta">
                            <h4 class="shield-list-item-title"><?php echo Text::e($title); ?></h4>
                            <p class="shield-list-item-desc"><?php echo Text::e($desc); ?></p>
                        </div>
                        <div class="shield-list-item-control">
                            <label class="shield-switch">
                                <input type="checkbox" name="<?php echo Text::e($key); ?>" value="1"<?php echo $settings[$key] === '1' ? ' checked' : ''; ?>>
                                <span class="shield-slider"></span>
                            </label>
                        </div>
                    </div>
                <?php endforeach; ?>
            </div>
        </div>

        <div class="shield-card">
            <div class="shield-card-header">
                <h3 class="shield-card-title">AI 爬虫与自动化工具</h3>
                <p class="shield-card-desc">配置 AI 爬虫与自动化工具的识别策略。</p>
            </div>
            <div class="shield-list">
                <div class="shield-block-item">
                    <div class="shield-matrix">
                        <label class="shield-field">
                            <span>AI 爬虫默认策略</span>
                            <select name="aiBotPolicy" class="shield-input">
                                <option value="observe"<?php echo $settings['aiBotPolicy'] === 'observe' ? ' selected' : ''; ?>>仅观察</option>
                                <option value="challenge"<?php echo $settings['aiBotPolicy'] === 'challenge' ? ' selected' : ''; ?>>基础验证</option>
                                <option value="block"<?php echo $settings['aiBotPolicy'] === 'block' ? ' selected' : ''; ?>>直接拦截</option>
                                <option value="allow"<?php echo $settings['aiBotPolicy'] === 'allow' ? ' selected' : ''; ?>>直接放行</option>
                            </select>
                        </label>
                        <label class="shield-field">
                            <span>自动化工具策略</span>
                            <select name="scriptClientPolicy" class="shield-input">
                                <option value="observe"<?php echo $settings['scriptClientPolicy'] === 'observe' ? ' selected' : ''; ?>>仅观察</option>
                                <option value="challenge"<?php echo $settings['scriptClientPolicy'] === 'challenge' ? ' selected' : ''; ?>>基础验证</option>
                                <option value="block"<?php echo $settings['scriptClientPolicy'] === 'block' ? ' selected' : ''; ?>>直接拦截</option>
                            </select>
                        </label>
                    </div>
                </div>
                <div class="shield-grid-2 shield-grid-pad">
                    <div class="shield-stack">
                        <label class="shield-field">
                            <span>AI 爬虫放行标识</span>
                            <textarea name="aiBotAllowlist" class="shield-input mono" rows="6" placeholder="Google-Extended&#10;ExampleBot"><?php echo Text::e((string) $settings['aiBotAllowlist']); ?></textarea>
                        </label>
                    </div>
                    <div class="shield-stack">
                        <label class="shield-field">
                            <span>自动化工具放行标识</span>
                            <textarea name="scriptClientAllowlist" class="shield-input mono" rows="6" placeholder="InternalMonitor&#10;HealthCheck"><?php echo Text::e((string) $settings['scriptClientAllowlist']); ?></textarea>
                        </label>
                    </div>
                </div>
                <div class="shield-block-item">
                    <div class="shield-list-item-meta">
                        <h4 class="shield-list-item-title">AI 爬虫单独规则</h4>
                        <p class="shield-list-item-desc">格式：`bot:policy` 或 `bot=policy`。配置后将覆盖默认策略。支持 `gptbot`、`chatgpt-user`、`claudebot`、`perplexity`、`bytespider`、`qwen`、`amazonbot`、`ccbot`。</p>
                    </div>
                    <textarea name="aiBotRules" class="shield-input mono" rows="6" placeholder="gptbot:challenge&#10;claudebot:block&#10;bytespider:observe"><?php echo Text::e((string) $settings['aiBotRules']); ?></textarea>
                </div>
            </div>
        </div>

        <div class="shield-card">
            <div class="shield-card-header">
                <h3 class="shield-card-title">浏览器一致性识别</h3>
                <p class="shield-card-desc">配置浏览器请求一致性识别规则。</p>
            </div>
            <div class="shield-list">
                <?php foreach ([
                    ['browserCheck', '浏览器最低版本要求', '对浏览器版本低于设定值的请求追加风险判定。'],
                    ['secFetchCheck', 'Sec-Fetch 校验', '对缺少 Sec-Fetch 请求头的浏览器请求追加风险判定。'],
                    ['headerCompleteness', '浏览器基础头完整度', '检查 Accept、Accept-Language、Accept-Encoding 等基础请求头。'],
                    ['httpVersionCheck', 'HTTP/1.x 风险识别', '将异常的 HTTP/1.x 请求作为附加风险信号。'],
                    ['blockProxy', '代理头识别', '识别未受信来源携带的代理头信息。'],
                ] as [$key, $title, $desc]): ?>
                    <div class="shield-list-item">
                        <div class="shield-list-item-meta">
                            <h4 class="shield-list-item-title"><?php echo Text::e($title); ?></h4>
                            <p class="shield-list-item-desc"><?php echo Text::e($desc); ?></p>
                        </div>
                        <div class="shield-list-item-control">
                            <label class="shield-switch">
                                <input type="checkbox" name="<?php echo Text::e($key); ?>" value="1"<?php echo $settings[$key] === '1' ? ' checked' : ''; ?>>
                                <span class="shield-slider"></span>
                            </label>
                        </div>
                    </div>
                <?php endforeach; ?>

                <div class="shield-block-item">
                    <div class="shield-list-item-meta">
                        <h4 class="shield-list-item-title">最低浏览器版本</h4>
                        <p class="shield-list-item-desc">仅在启用“浏览器最低版本要求”时生效。</p>
                    </div>
                    <div class="shield-matrix">
                        <label class="shield-field">
                            <span>Chrome</span>
                            <input type="number" name="minChrome" min="1" max="300" value="<?php echo (int) $settings['minChrome']; ?>" class="shield-input">
                        </label>
                        <label class="shield-field">
                            <span>Firefox</span>
                            <input type="number" name="minFirefox" min="1" max="300" value="<?php echo (int) $settings['minFirefox']; ?>" class="shield-input">
                        </label>
                        <label class="shield-field">
                            <span>Edge</span>
                            <input type="number" name="minEdge" min="1" max="300" value="<?php echo (int) $settings['minEdge']; ?>" class="shield-input">
                        </label>
                        <label class="shield-field">
                            <span>Safari</span>
                            <input type="number" name="minSafari" min="1" max="100" value="<?php echo (int) $settings['minSafari']; ?>" class="shield-input">
                        </label>
                        <label class="shield-field shield-field-wide">
                            <span>蜘蛛验证缓存小时</span>
                            <input type="number" name="spiderCacheHours" min="1" max="168" value="<?php echo (int) $settings['spiderCacheHours']; ?>" class="shield-input">
                        </label>
                    </div>
                </div>

                <div class="shield-block-item">
                    <div class="shield-list-item-meta">
                        <h4 class="shield-list-item-title">受信代理与 XML-RPC 白名单</h4>
                        <p class="shield-list-item-desc">填写受信代理或固定客户端的 IP / CIDR；留空表示不单独放行。</p>
                    </div>
                    <div class="shield-grid-2 shield-grid-pad">
                        <div class="shield-stack">
                            <label class="shield-field">
                                <span>受信代理 IP / CIDR</span>
                                <textarea name="proxyTrusted" class="shield-input mono" rows="5"><?php echo Text::e((string) $settings['proxyTrusted']); ?></textarea>
                            </label>
                        </div>
                        <div class="shield-stack">
                            <label class="shield-field">
                                <span>XML-RPC 白名单 IP / CIDR</span>
                                <textarea name="xmlrpcAllowlist" class="shield-input mono" rows="5"><?php echo Text::e((string) $settings['xmlrpcAllowlist']); ?></textarea>
                            </label>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <div class="shield-card">
            <div class="shield-card-header">
                <h3 class="shield-card-title">名单与陷阱</h3>
                <p class="shield-card-desc">配置白名单、黑名单与扫描陷阱路径。</p>
            </div>
            <div class="shield-list">
                <div class="shield-grid-2 shield-grid-pad">
                    <div class="shield-stack">
                        <label class="shield-field">
                            <span>IP 白名单</span>
                            <textarea name="ipAllowlist" class="shield-input mono" rows="6"><?php echo Text::e((string) $settings['ipAllowlist']); ?></textarea>
                        </label>
                    </div>
                    <div class="shield-stack">
                        <label class="shield-field">
                            <span>IP 黑名单</span>
                            <textarea name="ipDenylist" class="shield-input mono" rows="6"><?php echo Text::e((string) $settings['ipDenylist']); ?></textarea>
                        </label>
                    </div>
                    <div class="shield-stack">
                        <label class="shield-field">
                            <span>UA 白名单</span>
                            <textarea name="uaAllowlist" class="shield-input mono" rows="6"><?php echo Text::e((string) $settings['uaAllowlist']); ?></textarea>
                        </label>
                    </div>
                    <div class="shield-stack">
                        <label class="shield-field">
                            <span>UA 黑名单</span>
                            <textarea name="uaDenylist" class="shield-input mono" rows="6"><?php echo Text::e((string) $settings['uaDenylist']); ?></textarea>
                        </label>
                    </div>
                </div>
                <div class="shield-block-item">
                    <div class="shield-list-item-meta">
                        <h4 class="shield-list-item-title">扫描器陷阱路径</h4>
                            <p class="shield-list-item-desc">命中这些路径的请求将作为扫描行为记录并处理。支持使用 `*` 作为通配符。</p>
                    </div>
                    <textarea name="trapPaths" class="shield-input mono" rows="8"><?php echo Text::e((string) $settings['trapPaths']); ?></textarea>
                </div>
            </div>
        </div>
    </div>

    <div class="tr-panel-pane<?php echo $currentTab === 'challenge' ? ' is-active' : ''; ?>" data-tab="challenge">
        <div class="shield-card">
            <div class="shield-card-header">
                <h3 class="shield-card-title">挑战与限频</h3>
                <p class="shield-card-desc">配置普通页面、登录、评论与 XML-RPC 请求的限频和验证规则。</p>
            </div>
            <div class="shield-list">
                <div class="shield-block-item">
                    <div class="shield-list-item-meta">
                        <h4 class="shield-list-item-title">限频阈值</h4>
                        <p class="shield-list-item-desc">单位分别为秒和次数，用于定义各类请求的触发阈值。</p>
                    </div>
                    <div class="shield-matrix">
                        <label class="shield-field">
                            <span>站点窗口</span>
                            <input type="number" name="generalWindow" min="10" max="3600" value="<?php echo (int) $settings['generalWindow']; ?>" class="shield-input">
                        </label>
                        <label class="shield-field">
                            <span>站点次数</span>
                            <input type="number" name="generalLimit" min="1" max="10000" value="<?php echo (int) $settings['generalLimit']; ?>" class="shield-input">
                        </label>
                        <label class="shield-field">
                            <span>登录窗口</span>
                            <input type="number" name="loginWindow" min="60" max="86400" value="<?php echo (int) $settings['loginWindow']; ?>" class="shield-input">
                        </label>
                        <label class="shield-field">
                            <span>登录次数</span>
                            <input type="number" name="loginLimit" min="1" max="200" value="<?php echo (int) $settings['loginLimit']; ?>" class="shield-input">
                        </label>
                        <label class="shield-field">
                            <span>评论窗口</span>
                            <input type="number" name="commentWindow" min="10" max="3600" value="<?php echo (int) $settings['commentWindow']; ?>" class="shield-input">
                        </label>
                        <label class="shield-field">
                            <span>评论次数</span>
                            <input type="number" name="commentLimit" min="1" max="200" value="<?php echo (int) $settings['commentLimit']; ?>" class="shield-input">
                        </label>
                        <label class="shield-field">
                            <span>XML-RPC 窗口</span>
                            <input type="number" name="xmlrpcWindow" min="10" max="86400" value="<?php echo (int) $settings['xmlrpcWindow']; ?>" class="shield-input">
                        </label>
                        <label class="shield-field">
                            <span>XML-RPC 次数</span>
                            <input type="number" name="xmlrpcLimit" min="1" max="200" value="<?php echo (int) $settings['xmlrpcLimit']; ?>" class="shield-input">
                        </label>
                        <label class="shield-field">
                            <span>恶意累计阈值</span>
                            <input type="number" name="badLimit" min="1" max="100" value="<?php echo (int) $settings['badLimit']; ?>" class="shield-input">
                        </label>
                        <label class="shield-field">
                            <span>挑战等待秒数</span>
                            <input type="number" name="challengeWait" min="0" max="30" value="<?php echo (int) $settings['challengeWait']; ?>" class="shield-input">
                        </label>
                        <label class="shield-field">
                            <span>自动封禁小时</span>
                            <input type="number" name="autoBanHours" min="1" max="720" value="<?php echo (int) $settings['autoBanHours']; ?>" class="shield-input">
                        </label>
                        <label class="shield-field">
                            <span>陷阱封禁小时</span>
                            <input type="number" name="trapBanHours" min="1" max="720" value="<?php echo (int) $settings['trapBanHours']; ?>" class="shield-input">
                        </label>
                    </div>
                </div>
            </div>
        </div>

        <div class="shield-card">
            <div class="shield-card-header">
                <h3 class="shield-card-title">写请求与登录保护</h3>
                <p class="shield-card-desc">配置写请求与登录来源的专项防护规则。</p>
            </div>
            <div class="shield-list">
                <?php foreach ([
                    ['writeProtect', '写请求专项限频', '对 POST、PUT、PATCH、DELETE 请求单独统计并限制短时高频提交。'],
                    ['writeReplayCheck', '写请求重放检测', '识别同一来源在短时间内重复提交相同请求体的行为。'],
                    ['loginSprayCheck', '撞库喷洒识别', '识别同一来源在短时间内尝试多个账号的登录行为。'],
                ] as [$key, $title, $desc]): ?>
                    <div class="shield-list-item">
                        <div class="shield-list-item-meta">
                            <h4 class="shield-list-item-title"><?php echo Text::e($title); ?></h4>
                            <p class="shield-list-item-desc"><?php echo Text::e($desc); ?></p>
                        </div>
                        <div class="shield-list-item-control">
                            <label class="shield-switch">
                                <input type="checkbox" name="<?php echo Text::e($key); ?>" value="1"<?php echo $settings[$key] === '1' ? ' checked' : ''; ?>>
                                <span class="shield-slider"></span>
                            </label>
                        </div>
                    </div>
                <?php endforeach; ?>
                <div class="shield-block-item">
                    <div class="shield-matrix">
                        <label class="shield-field">
                            <span>写请求窗口</span>
                            <input type="number" name="writeWindow" min="10" max="3600" value="<?php echo (int) $settings['writeWindow']; ?>" class="shield-input">
                        </label>
                        <label class="shield-field">
                            <span>写请求次数</span>
                            <input type="number" name="writeLimit" min="1" max="10000" value="<?php echo (int) $settings['writeLimit']; ?>" class="shield-input">
                        </label>
                        <label class="shield-field">
                            <span>重放窗口</span>
                            <input type="number" name="writeReplayWindow" min="30" max="86400" value="<?php echo (int) $settings['writeReplayWindow']; ?>" class="shield-input">
                        </label>
                        <label class="shield-field">
                            <span>重放次数</span>
                            <input type="number" name="writeReplayLimit" min="1" max="1000" value="<?php echo (int) $settings['writeReplayLimit']; ?>" class="shield-input">
                        </label>
                        <label class="shield-field">
                            <span>写请求处理</span>
                            <select name="writeChallengeMode" class="shield-input">
                                <option value="challenge"<?php echo $settings['writeChallengeMode'] === 'challenge' ? ' selected' : ''; ?>>基础验证</option>
                                <option value="block"<?php echo $settings['writeChallengeMode'] === 'block' ? ' selected' : ''; ?>>直接拦截</option>
                            </select>
                        </label>
                        <label class="shield-field">
                            <span>登录来源窗口</span>
                            <input type="number" name="loginIpWindow" min="60" max="86400" value="<?php echo (int) $settings['loginIpWindow']; ?>" class="shield-input">
                        </label>
                        <label class="shield-field">
                            <span>登录来源次数</span>
                            <input type="number" name="loginIpLimit" min="2" max="500" value="<?php echo (int) $settings['loginIpLimit']; ?>" class="shield-input">
                        </label>
                        <label class="shield-field">
                            <span>撞库账号阈值</span>
                            <input type="number" name="loginSprayUserLimit" min="2" max="100" value="<?php echo (int) $settings['loginSprayUserLimit']; ?>" class="shield-input">
                        </label>
                    </div>
                </div>
            </div>
        </div>

        <div class="shield-card">
            <div class="shield-card-header">
                <h3 class="shield-card-title">搜索防滥用</h3>
                <p class="shield-card-desc">配置搜索请求的频率与关键词规则。</p>
            </div>
            <div class="shield-list">
                <div class="shield-list-item">
                    <div class="shield-list-item-meta">
                        <h4 class="shield-list-item-title">启用搜索保护</h4>
                        <p class="shield-list-item-desc">对搜索请求执行限频、关键词枚举与长度检查。</p>
                    </div>
                    <div class="shield-list-item-control">
                        <label class="shield-switch">
                            <input type="checkbox" name="searchProtect" value="1"<?php echo $settings['searchProtect'] === '1' ? ' checked' : ''; ?>>
                            <span class="shield-slider"></span>
                        </label>
                    </div>
                </div>
                <div class="shield-block-item">
                    <div class="shield-matrix">
                        <label class="shield-field">
                            <span>搜索窗口</span>
                            <input type="number" name="searchWindow" min="30" max="86400" value="<?php echo (int) $settings['searchWindow']; ?>" class="shield-input">
                        </label>
                        <label class="shield-field">
                            <span>搜索次数</span>
                            <input type="number" name="searchLimit" min="1" max="1000" value="<?php echo (int) $settings['searchLimit']; ?>" class="shield-input">
                        </label>
                        <label class="shield-field">
                            <span>关键词枚举阈值</span>
                            <input type="number" name="searchKeywordBurst" min="1" max="200" value="<?php echo (int) $settings['searchKeywordBurst']; ?>" class="shield-input">
                        </label>
                        <label class="shield-field">
                            <span>最短关键词长度</span>
                            <input type="number" name="searchMinKeywordLen" min="1" max="64" value="<?php echo (int) $settings['searchMinKeywordLen']; ?>" class="shield-input">
                        </label>
                        <label class="shield-field">
                            <span>最长关键词长度</span>
                            <input type="number" name="searchMaxKeywordLen" min="1" max="255" value="<?php echo (int) $settings['searchMaxKeywordLen']; ?>" class="shield-input">
                        </label>
                    </div>
                </div>
            </div>
        </div>

        <div class="shield-card">
            <div class="shield-card-header">
                <h3 class="shield-card-title">评论与上传保护</h3>
                <p class="shield-card-desc">配置评论提交与上传请求的基础保护规则。</p>
            </div>
            <div class="shield-list">
                <?php foreach ([
                    ['commentRequireChallenge', '评论请求需要先验证', '非登录用户评论在命中高风险条件时需先完成基础验证。'],
                    ['uploadDoubleExt', '拦截双扩展上传', '拦截包含双扩展名的上传文件。'],
                    ['uploadScan', '扫描上传内容特征', '对上传内容进行轻量检测，识别脚本片段与高风险标记。'],
                ] as [$key, $title, $desc]): ?>
                    <div class="shield-list-item">
                        <div class="shield-list-item-meta">
                            <h4 class="shield-list-item-title"><?php echo Text::e($title); ?></h4>
                            <p class="shield-list-item-desc"><?php echo Text::e($desc); ?></p>
                        </div>
                        <div class="shield-list-item-control">
                            <label class="shield-switch">
                                <input type="checkbox" name="<?php echo Text::e($key); ?>" value="1"<?php echo $settings[$key] === '1' ? ' checked' : ''; ?>>
                                <span class="shield-slider"></span>
                            </label>
                        </div>
                    </div>
                <?php endforeach; ?>

                <div class="shield-block-item">
                    <div class="shield-matrix">
                        <label class="shield-field">
                            <span>评论最短秒数</span>
                            <input type="number" name="commentMinSeconds" min="0" max="60" value="<?php echo (int) $settings['commentMinSeconds']; ?>" class="shield-input">
                        </label>
                        <label class="shield-field">
                            <span>评论最大链接数</span>
                            <input type="number" name="commentLinks" min="0" max="50" value="<?php echo (int) $settings['commentLinks']; ?>" class="shield-input">
                        </label>
                        <label class="shield-field">
                            <span>上传大小上限 KB</span>
                            <input type="number" name="uploadMaxKb" min="0" max="102400" value="<?php echo (int) $settings['uploadMaxKb']; ?>" class="shield-input">
                        </label>
                    </div>
                </div>
            </div>
        </div>

        <div class="shield-card">
            <div class="shield-card-header">
                <h3 class="shield-card-title">HTTP Basic Auth 与行为序列</h3>
                <p class="shield-card-desc">配置路径访问验证与行为序列识别规则。</p>
            </div>
            <div class="shield-list">
                <?php foreach ([
                    ['basicAuthEnable', '启用 HTTP Basic Auth', '命中受保护路径时要求输入用户名和密码。'],
                    ['basicAuthBypassLoggedAdmin', '已登录管理员绕过', '管理员已登录后台时不再重复进行 HTTP Basic Auth 验证。'],
                    ['sequenceProtect', '启用行为序列反爬', '根据访问路径分布、搜索混合度与静态资源请求情况识别低速采集行为。'],
                    ['sequenceNoAssetBias', '无静态资源加权', '长时间仅请求页面而缺少静态资源请求时，提高行为分数。'],
                ] as [$key, $title, $desc]): ?>
                    <div class="shield-list-item">
                        <div class="shield-list-item-meta">
                            <h4 class="shield-list-item-title"><?php echo Text::e($title); ?></h4>
                            <p class="shield-list-item-desc"><?php echo Text::e($desc); ?></p>
                        </div>
                        <div class="shield-list-item-control">
                            <label class="shield-switch">
                                <input type="checkbox" name="<?php echo Text::e($key); ?>" value="1"<?php echo $settings[$key] === '1' ? ' checked' : ''; ?>>
                                <span class="shield-slider"></span>
                            </label>
                        </div>
                    </div>
                <?php endforeach; ?>
                <div class="shield-grid-2 shield-grid-pad">
                    <div class="shield-stack">
                        <label class="shield-field">
                            <span>Basic Auth 用户名</span>
                            <input type="text" name="basicAuthUser" value="<?php echo Text::e((string) $settings['basicAuthUser']); ?>" class="shield-input">
                        </label>
                    </div>
                    <div class="shield-stack">
                        <label class="shield-field">
                            <span>Basic Auth 密码</span>
                            <input type="password" name="basicAuthPass" value="" class="shield-input" autocomplete="new-password" placeholder="留空则保持原密码不变">
                        </label>
                    </div>
                    <div class="shield-stack">
                        <label class="shield-field">
                            <span>Basic Auth 提示名称</span>
                            <input type="text" name="basicAuthRealm" value="<?php echo Text::e((string) $settings['basicAuthRealm']); ?>" class="shield-input">
                        </label>
                    </div>
                    <div class="shield-stack">
                        <label class="shield-field">
                            <span>行为序列处理策略</span>
                            <select name="sequencePolicy" class="shield-input">
                                <option value="observe"<?php echo $settings['sequencePolicy'] === 'observe' ? ' selected' : ''; ?>>仅观察</option>
                                <option value="challenge"<?php echo $settings['sequencePolicy'] === 'challenge' ? ' selected' : ''; ?>>基础验证</option>
                                <option value="block"<?php echo $settings['sequencePolicy'] === 'block' ? ' selected' : ''; ?>>直接拦截</option>
                            </select>
                        </label>
                    </div>
                </div>
                <div class="shield-block-item">
                    <div class="shield-list-item-meta">
                        <h4 class="shield-list-item-title">Basic Auth 路径规则</h4>
                        <p class="shield-list-item-desc">支持精确路径和 `*` 通配符，例如 `/admin/*`、`/preview/*`、`/internal/tool`。</p>
                    </div>
                    <textarea name="basicAuthRules" class="shield-input mono" rows="6" placeholder="/admin/*&#10;/preview/*"><?php echo Text::e((string) $settings['basicAuthRules']); ?></textarea>
                </div>
                <div class="shield-block-item">
                    <div class="shield-matrix">
                        <label class="shield-field">
                            <span>行为窗口</span>
                            <input type="number" name="sequenceWindow" min="60" max="86400" value="<?php echo (int) $settings['sequenceWindow']; ?>" class="shield-input">
                        </label>
                        <label class="shield-field">
                            <span>挑战分数</span>
                            <input type="number" name="sequenceChallengeScore" min="20" max="500" value="<?php echo (int) $settings['sequenceChallengeScore']; ?>" class="shield-input">
                        </label>
                        <label class="shield-field">
                            <span>拦截分数</span>
                            <input type="number" name="sequenceScoreLimit" min="50" max="500" value="<?php echo (int) $settings['sequenceScoreLimit']; ?>" class="shield-input">
                        </label>
                        <label class="shield-field">
                            <span>唯一路径阈值</span>
                            <input type="number" name="sequenceUniquePathLimit" min="5" max="500" value="<?php echo (int) $settings['sequenceUniquePathLimit']; ?>" class="shield-input">
                        </label>
                        <label class="shield-field">
                            <span>混合类型阈值</span>
                            <input type="number" name="sequenceSearchMixLimit" min="2" max="100" value="<?php echo (int) $settings['sequenceSearchMixLimit']; ?>" class="shield-input">
                        </label>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <div class="tr-panel-pane<?php echo $currentTab === 'access' ? ' is-active' : ''; ?>" data-tab="access">
        <div class="shield-card">
            <div class="shield-card-header">
                <h3 class="shield-card-title">受限访问规则</h3>
                <p class="shield-card-desc">配置需要登录或指定角色后方可访问的内容与路径。</p>
            </div>
            <div class="shield-list">
                <div class="shield-block-item">
                    <?php if (!empty($accessSummary['rules'])): ?>
                        <div class="shield-compact-list">
                            <?php foreach ((array) $accessSummary['rules'] as $item): ?>
                                <div class="shield-compact-item">
                                    <strong>第 <?php echo (int) ($item['line'] ?? 0); ?> 行</strong>
                                    <span><?php echo Text::e((string) ($item['summary'] ?? '')); ?></span>
                                </div>
                            <?php endforeach; ?>
                        </div>
                    <?php elseif (($accessSummary['issueCount'] ?? 0) === 0): ?>
                        <p class="shield-list-item-desc">当前未配置访问规则。保存后，此处将显示规则摘要。</p>
                    <?php endif; ?>
                    <?php if (!empty($accessSummary['issues'])): ?>
                        <div class="shield-issue-list">
                            <?php foreach ((array) $accessSummary['issues'] as $issue): ?>
                                <div class="shield-issue-item"><?php echo Text::e((string) $issue); ?></div>
                            <?php endforeach; ?>
                        </div>
                    <?php endif; ?>
                </div>
                <div class="shield-block-item">
                    <div class="shield-list-item-meta">
                        <h4 class="shield-list-item-title">规则列表</h4>
                        <p class="shield-list-item-desc">按书写顺序匹配，命中后停止继续匹配。格式：匹配对象 =&gt; 需要权限 =&gt; 处理方式。</p>
                    </div>
                    <div class="shield-access-guide">
                        <div class="shield-access-guide-item">
                            <strong>匹配对象</strong>
                            <p class="shield-access-guide-desc">支持路径和内容实体。</p>
                            <div class="shield-access-guide-tags">
                                <span class="shield-access-guide-tag">/member/*</span>
                                <span class="shield-access-guide-tag">slug:vip</span>
                                <span class="shield-access-guide-tag">cid:123</span>
                                <span class="shield-access-guide-tag">category:private</span>
                                <span class="shield-access-guide-tag">tag:members</span>
                                <span class="shield-access-guide-tag">type:post</span>
                            </div>
                        </div>
                        <div class="shield-access-guide-item">
                            <strong>需要权限</strong>
                            <p class="shield-access-guide-desc">支持登录态和角色写法。</p>
                            <div class="shield-access-guide-tags">
                                <span class="shield-access-guide-tag">login</span>
                                <span class="shield-access-guide-tag">role:subscriber</span>
                                <span class="shield-access-guide-tag">role:editor|administrator</span>
                            </div>
                        </div>
                        <div class="shield-access-guide-item">
                            <strong>处理方式</strong>
                            <p class="shield-access-guide-desc">支持 HTML、403 和跳转。</p>
                            <div class="shield-access-guide-tags">
                                <span class="shield-access-guide-tag">html</span>
                                <span class="shield-access-guide-tag">403</span>
                                <span class="shield-access-guide-tag">redirect</span>
                                <span class="shield-access-guide-tag">redirect:/login.php</span>
                            </div>
                        </div>
                    </div>
                    <textarea
                        name="accessRules"
                        class="shield-input mono"
                        rows="10"
                        placeholder="/member/* => login => html&#10;slug:vip => role:subscriber => redirect&#10;cid:123 => role:editor|administrator => 403"
                    ><?php echo Text::e((string) $settings['accessRules']); ?></textarea>
                </div>
                <div class="shield-grid-2 shield-grid-pad">
                    <div class="shield-stack">
                        <label class="shield-field">
                            <span>默认提示 HTML</span>
                            <textarea name="accessHtml" class="shield-input mono" rows="8"><?php echo Text::e((string) $settings['accessHtml']); ?></textarea>
                        </label>
                    </div>
                    <div class="shield-stack">
                        <label class="shield-field">
                            <span>默认跳转地址</span>
                            <input type="text" name="accessRedirect" value="<?php echo Text::e((string) $settings['accessRedirect']); ?>" class="shield-input">
                        </label>
                    </div>
                </div>
            </div>
        </div>
    </div>
    <div id="renewshield-sticky" class="tr-panel-sticky">
        <div class="shield-sticky-actions">
            <button type="submit" class="btn primary">保存当前配置</button>
        </div>
    </div>
</form>
