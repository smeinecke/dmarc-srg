<?php

/**
 * dmarc-srg - A php parser, viewer and summary report generator for incoming DMARC reports.
 * Copyright (C) 2020 Aleksey Andreev (liuch)
 *
 * Available at:
 * https://github.com/liuch/dmarc-srg
 *
 * This program is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation, either version 3 of the License.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of  MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * =========================
 *
 * This file contains logging classes
 *
 * @category Log
 * @package  DmarcSrg
 * @author   Aleksey Andreev (liuch)
 * @license  https://www.gnu.org/licenses/gpl-3.0.html GNU/GPLv3
 */

namespace Liuch\DmarcSrg;

class LogLevel
{
    const ERROR = 0;
    const WARN = 1;
    const INFO = 2;
    const DEBUG = 3;
}

class Log
{
    private static $log_level = LogLevel::INFO;

    private static function log_level_str(int $level)
    {
        switch ($level) {
            case LogLevel::ERROR:
                return 'ERROR';
            case LogLevel::WARN:
                return 'WARNING';
            case LogLevel::INFO:
                return 'INFO';
            case LogLevel::DEBUG:
                return 'DEBUG';
        }
    }

    public static function print(int $level, ...$messages)
    {
        if ($level > self::$log_level) {
            return;
        }

        $ll = [];
        foreach ($messages as $msg) {
            if (is_null($msg)) {
                continue;
            }

            if (!is_string($msg)) {
                $msg = json_encode($msg);
            }

            $ll[] = $msg;
        }

        printf("%s [%7s] %s%s", date('Y-m-d H:m:i'), self::log_level_str($level), join(' ', $ll), PHP_EOL);
    }

    public static function setLogLevel(int $level)
    {
        self::$log_level = $level;
    }

    public static function info(...$messages)
    {
        return self::print(LogLevel::INFO, ...$messages);
    }

    public static function warn(...$messages)
    {
        return self::print(LogLevel::WARN, ...$messages);
    }

    public static function error(...$messages)
    {
        return self::print(LogLevel::ERROR, ...$messages);
    }

    public static function debug(...$messages)
    {
        return self::print(LogLevel::DEBUG, ...$messages);
    }
}
