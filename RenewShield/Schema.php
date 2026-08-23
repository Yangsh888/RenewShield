<?php

namespace TypechoPlugin\RenewShield;

use Typecho\Db;
use Utils\Schema as CoreSchema;

class Schema
{
    public static function ensure(Db $db): void
    {
        $dialect = CoreSchema::dialect($db);
        $prefix = $db->getPrefix();

        self::ensureLogs($db, $dialect, $prefix . 'renew_shield_logs');
        self::ensureState($db, $dialect, $prefix . 'renew_shield_state');
    }

    private static function ensureLogs(Db $db, string $dialect, string $table): void
    {
        $name = CoreSchema::quote($table, $dialect);

        $db->query(match ($dialect) {
            'sqlite' => 'CREATE TABLE IF NOT EXISTS ' . $name . ' ('
                . '"id" INTEGER PRIMARY KEY AUTOINCREMENT,'
                . '"scope" TEXT NOT NULL,'
                . '"action" TEXT NOT NULL,'
                . '"decision" TEXT NOT NULL,'
                . '"rule_key" TEXT NOT NULL,'
                . '"score" INTEGER NOT NULL DEFAULT 0,'
                . '"method" TEXT NOT NULL,'
                . '"ip" TEXT DEFAULT NULL,'
                . '"path" TEXT DEFAULT NULL,'
                . '"ua" TEXT DEFAULT NULL,'
                . '"message" TEXT NOT NULL,'
                . '"payload" TEXT DEFAULT NULL,'
                . '"created_at" INTEGER NOT NULL'
                . ')',
            'pgsql' => 'CREATE TABLE IF NOT EXISTS ' . $name . ' ('
                . '"id" BIGSERIAL PRIMARY KEY,'
                . '"scope" VARCHAR(24) NOT NULL,'
                . '"action" VARCHAR(24) NOT NULL,'
                . '"decision" VARCHAR(16) NOT NULL,'
                . '"rule_key" VARCHAR(64) NOT NULL,'
                . '"score" INT NOT NULL DEFAULT 0,'
                . '"method" VARCHAR(12) NOT NULL,'
                . '"ip" VARCHAR(45) DEFAULT NULL,'
                . '"path" TEXT DEFAULT NULL,'
                . '"ua" TEXT DEFAULT NULL,'
                . '"message" VARCHAR(255) NOT NULL,'
                . '"payload" TEXT DEFAULT NULL,'
                . '"created_at" INTEGER NOT NULL'
                . ')',
            default => 'CREATE TABLE IF NOT EXISTS ' . $name . ' ('
                . '`id` bigint unsigned NOT NULL auto_increment,'
                . '`scope` varchar(24) NOT NULL,'
                . '`action` varchar(24) NOT NULL,'
                . '`decision` varchar(16) NOT NULL,'
                . '`rule_key` varchar(64) NOT NULL,'
                . '`score` int NOT NULL DEFAULT 0,'
                . '`method` varchar(12) NOT NULL,'
                . '`ip` varchar(45) DEFAULT NULL,'
                . '`path` varchar(1024) DEFAULT NULL,'
                . '`ua` varchar(512) DEFAULT NULL,'
                . '`message` varchar(255) NOT NULL,'
                . '`payload` text DEFAULT NULL,'
                . '`created_at` int unsigned NOT NULL,'
                . 'PRIMARY KEY (`id`)'
                . ') ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=' . CoreSchema::detectMysqlCollation($db),
        }, Db::WRITE);

        $index = static fn(string $mysql, string $other): string => $dialect === 'mysql' ? $mysql : $table . '_' . $other;

        CoreSchema::ensureIndex($db, $table, $index('idx_scope_created', 'scope_created'), ['scope', 'created_at']);
        CoreSchema::ensureIndex($db, $table, $index('idx_decision_created', 'decision_created'), ['decision', 'created_at']);
        CoreSchema::ensureIndex($db, $table, $index('idx_ip_created', 'ip_created'), ['ip', 'created_at']);
        CoreSchema::ensureIndex($db, $table, $index('idx_rule_created', 'rule_created'), ['rule_key', 'created_at']);
        CoreSchema::ensureIndex($db, $table, $index('idx_created', 'created'), ['created_at']);
    }

    private static function ensureState(Db $db, string $dialect, string $table): void
    {
        $name = CoreSchema::quote($table, $dialect);

        $db->query(match ($dialect) {
            'sqlite' => 'CREATE TABLE IF NOT EXISTS ' . $name . ' ('
                . '"id" INTEGER PRIMARY KEY AUTOINCREMENT,'
                . '"name_hash" TEXT NOT NULL,'
                . '"value" TEXT DEFAULT NULL,'
                . '"expires_at" INTEGER NOT NULL DEFAULT 0'
                . ')',
            'pgsql' => 'CREATE TABLE IF NOT EXISTS ' . $name . ' ('
                . '"id" BIGSERIAL PRIMARY KEY,'
                . '"name_hash" CHAR(40) NOT NULL,'
                . '"value" TEXT DEFAULT NULL,'
                . '"expires_at" INTEGER NOT NULL DEFAULT 0'
                . ')',
            default => 'CREATE TABLE IF NOT EXISTS ' . $name . ' ('
                . '`id` bigint unsigned NOT NULL auto_increment,'
                . '`name_hash` char(40) NOT NULL,'
                . '`value` mediumtext DEFAULT NULL,'
                . '`expires_at` int unsigned NOT NULL DEFAULT 0,'
                . 'PRIMARY KEY (`id`)'
                . ') ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=' . CoreSchema::detectMysqlCollation($db),
        }, Db::WRITE);

        $index = static fn(string $mysql, string $other): string => $dialect === 'mysql' ? $mysql : $table . '_' . $other;

        CoreSchema::ensureIndex($db, $table, $index('uniq_name_hash', 'name_hash'), ['name_hash'], true);
        CoreSchema::ensureIndex($db, $table, $index('idx_expires', 'expires'), ['expires_at']);
    }
}
