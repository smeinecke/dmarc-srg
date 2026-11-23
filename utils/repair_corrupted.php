<?php

/**
 * dmarc-srg - A php parser, viewer and summary report generator for incoming DMARC reports.
 * Copyright (C) 2026 Aleksey Andreev (liuch)
 *
 * Available at:
 * https://github.com/liuch/dmarc-srg
 *
 * This program is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option)
 * any later version.
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
 * This script detects report records that were corrupted by the database charset
 * conversion bug (binary IP addresses stored with '?' bytes instead of the
 * original data) and re-imports the corresponding reports from the configured
 * report sources: mailboxes, local directories, and remote filesystems.
 *
 * The parameters of the sources are read from the configuration file, the same
 * as for utils/fetch_reports.php.
 *
 * Some examples:
 * $ utils/repair_corrupted.php
 * lists reports containing corrupted records without changing anything.
 *
 * $ utils/repair_corrupted.php action=repair dry=1
 * searches the sources for the affected report files and shows what would be
 * repaired without changing the database.
 *
 * $ utils/repair_corrupted.php action=repair
 * deletes the corrupted reports and re-imports them from the found files.
 *
 * $ utils/repair_corrupted.php action=repair source=directory
 * re-imports only from the local directories.
 *
 * $ utils/repair_corrupted.php action=repair deep=1
 * parses every file in the sources to match reports by content. Useful when the
 * report log no longer contains file names, but much slower, especially for
 * mailboxes.
 *
 * @category Utilities
 * @package  DmarcSrg
 * @author   Aleksey Andreev (liuch)
 * @license  https://www.gnu.org/licenses/gpl-3.0.html GNU/GPLv3
 */

namespace Liuch\DmarcSrg;

use Liuch\DmarcSrg\Mail\MailBox;
use Liuch\DmarcSrg\Mail\MailBoxes;
use Liuch\DmarcSrg\Report\Report;
use Liuch\DmarcSrg\Sources\Source;
use Liuch\DmarcSrg\ReportFile\ReportFile;
use Liuch\DmarcSrg\Sources\SourceAction;
use Liuch\DmarcSrg\ReportLog\ReportLogItem;
use Liuch\DmarcSrg\Directories\DirectoryList;
use Liuch\DmarcSrg\Exception\SoftException;
use Liuch\DmarcSrg\RemoteFilesystems\RemoteFilesystemList;

require realpath(__DIR__ . '/..') . '/init.php';

if (Core::isWEB()) {
    echo 'Forbidden';
    exit(1);
}

if (!isset($argv)) {
    echo 'Cannot get the script arguments. Probably register_argc_argv is disabled.', PHP_EOL;
    exit(1);
}

$action = 'scan';
$source = null;
$deep   = false;
$dry    = false;
$usage  = false;
for ($i = 1; $i < count($argv); ++$i) {
    $av = explode('=', $argv[$i]);
    if (count($av) !== 2) {
        echo 'Invalid parameter format' . PHP_EOL;
        $usage = true;
        break;
    }
    switch ($av[0]) {
        case 'action':
            $action = $av[1];
            break;
        case 'source':
            $source = $av[1];
            break;
        case 'deep':
            $deep = in_array($av[1], [ '1', 'yes', 'true' ], true);
            break;
        case 'dry':
            $dry = in_array($av[1], [ '1', 'yes', 'true' ], true);
            break;
        default:
            echo 'Unknown parameter "' . $av[0] . '"' . PHP_EOL;
            $usage = true;
            break;
    }
}
if (!in_array($action, [ 'scan', 'repair' ], true)) {
    echo 'Invalid action "' . $action . '". "scan" or "repair" expected.' . PHP_EOL;
    $usage = true;
}
if ($source && !in_array($source, [ 'email', 'directory', 'remotefs' ])) {
    echo 'Invalid source type "' . $source . '". "email", "directory" or "remotefs" expected.' . PHP_EOL;
    $usage = true;
}
if ($usage) {
    echo PHP_EOL;
    echo "Usage: {$argv[0]} [action=scan|repair] [source=email|directory|remotefs] [deep=0|1] [dry=0|1]", PHP_EOL;
    exit(1);
}

$core = Core::instance();
$core->setCurrentUser('admin');

$db_conf = $core->config('database');
switch ($db_conf['type'] ?? '') {
    case 'mysql':
    case 'mariadb':
        $connector = new Database\Mariadb\Connector($db_conf);
        break;
    default:
        echo 'Unsupported database type: ' . ($db_conf['type'] ?? ''), PHP_EOL;
        exit(1);
}
$db   = $connector->dbh();
$tnrr = $connector->tablePrefix('rptrecords');
$tnrp = $connector->tablePrefix('reports');
$tndm = $connector->tablePrefix('domains');
$tnrl = $connector->tablePrefix('reportlog');

// Searching for reports that have records with corrupted binary IP addresses.
// Corrupted bytes were replaced by the database with 0x3F ('?') characters.
// Note that a valid IP address may also contain the 0x3F byte (octet 63), so
// some of the found reports may be false positives. Re-importing them is
// harmless and does not change their data.
$suspects = [];
$st = $db->query(
    "SELECT rp.id, rp.domain_id, d.fqdn, rp.org, rp.external_id, rp.begin_time, rp.seen, rp.loaded_time,"
    . " (SELECT COUNT(*) FROM {$tnrr} AS rr2 WHERE rr2.report_id = rp.id AND rr2.ip LIKE '%?%')"
    . " FROM {$tnrp} AS rp INNER JOIN {$tndm} AS d ON d.id = rp.domain_id"
    . " WHERE EXISTS (SELECT 1 FROM {$tnrr} AS rr WHERE rr.report_id = rp.id AND rr.ip LIKE '%?%')"
    . ' ORDER BY rp.begin_time'
);
while ($row = $st->fetch(\PDO::FETCH_NUM)) {
    $begin_ts = (new \DateTime($row[5], new \DateTimeZone('UTC')))->getTimestamp();
    $key = strtolower($row[2]) . "\x00" . $row[3] . "\x00" . $row[4] . "\x00" . $begin_ts;
    $suspects[$key] = [
        'id'        => intval($row[0]),
        'domain_id' => intval($row[1]),
        'fqdn'      => $row[2],
        'org'       => $row[3],
        'external'  => $row[4],
        'begin'     => $row[5],
        'seen'      => intval($row[6]),
        'loaded'    => $row[7],
        'bad'       => intval($row[8]),
        'hints'     => [],
        'status'    => 'pending',
        'detail'    => ''
    ];
}
$st->closeCursor();

if (count($suspects) === 0) {
    echo 'No corrupted report records found.', PHP_EOL;
    exit(0);
}

echo '=== CORRUPTED REPORTS ===', PHP_EOL;
foreach ($suspects as &$s) {
    echo "  * [{$s['id']}] {$s['fqdn']}; {$s['org']}; {$s['external']}; {$s['begin']};"
        . " corrupted records: {$s['bad']}", PHP_EOL;
}
unset($s);
echo 'Found ', count($suspects), ' report(s) to check.', PHP_EOL;
echo 'Note: IP addresses containing octet 63 may be false positives. Re-importing them is harmless.', PHP_EOL;

// Searching the report log for the names of the files the reports were loaded from.
$wanted = [];
$st = $db->prepare(
    "SELECT DISTINCT source, filename FROM {$tnrl}"
    . ' WHERE domain = ? AND external_id = ? AND success = 1 AND filename IS NOT NULL'
);
$uploaded = 0;
foreach ($suspects as &$s) {
    $st->execute([ $s['fqdn'], $s['external'] ]);
    while ($row = $st->fetch(\PDO::FETCH_NUM)) {
        $s['hints'][intval($row[0])][strval($row[1])] = true;
        $wanted[strval($row[1])] = true;
    }
    $st->closeCursor();
    if (isset($s['hints'][Source::SOURCE_UPLOADED_FILE])) {
        ++$uploaded;
    }
}
unset($s);

if ($action === 'scan') {
    echo PHP_EOL, '=== REPORT LOG HINTS ===', PHP_EOL;
    foreach ($suspects as &$s) {
        echo "  * [{$s['id']}] {$s['fqdn']} {$s['external']}:", PHP_EOL;
        if (count($s['hints']) === 0) {
            echo '      no file references found (the log may have been cleaned)', PHP_EOL;
        }
        foreach ($s['hints'] as $stype => $fnames) {
            echo '      ', ReportLogItem::sourceToString($stype), ': ', implode(', ', array_keys($fnames)), PHP_EOL;
        }
    }
    unset($s);
    echo PHP_EOL;
    echo 'Run this script with action=repair to re-import the reports from the configured sources.', PHP_EOL;
    exit(0);
}

// Returns a list of the child mailbox or subdirectory names the files could
// have been moved to after processing, according to the fetcher settings.
$moveTargets = function (string $section, int $flags, string $d_done, string $d_fail) use ($core): array {
    $targets = [];
    foreach ([ 'when_done' => $d_done, 'when_failed' => $d_fail ] as $key => $def) {
        $acts = SourceAction::fromSetting($core->config("fetcher/{$section}/{$key}", ''), $flags, $def);
        foreach ($acts as $a) {
            if ($a->type === SourceAction::ACTION_MOVE) {
                $targets[$a->param] = true;
            }
        }
    }
    return array_keys($targets);
};

// Returns the unique identity key of a parsed report
$identity = function ($report): string {
    return strtolower($report->domain) . "\x00" . $report->org_name . "\x00"
        . $report->report_id . "\x00" . $report->date['begin']->getTimestamp();
};

$maxSize = $core->config('fetcher/max_report_size', 10485760);
$stats   = [ 'repaired' => 0, 'found' => 0, 'parse_errors' => 0, 'mismatched' => 0 ];

$repair = function (array &$s, $report, string $fname, int $stype) use ($db, $connector, $tnrp): void {
    $filter = [ 'id' => $s['id'] ];
    $order  = [];
    $limit  = [ 'offset' => 0, 'count' => 0 ];
    $connector->getMapper('report')->delete($filter, $order, $limit);
    $report->save($fname);
    $st = $db->prepare(
        "UPDATE {$tnrp} SET seen = ?, loaded_time = ?"
        . ' WHERE domain_id = ? AND begin_time = ? AND org = ? AND external_id = ?'
    );
    $st->execute([ $s['seen'], $s['loaded'], $s['domain_id'], $s['begin'], $s['org'], $s['external'] ]);
    $st->closeCursor();
    ReportLogItem::success($stype, $report, $fname, 'Re-imported to repair corrupted records')->save();
};

$processFile = function ($rfile, int $stype, string $where) use (
    &$suspects, &$stats, $wanted, $deep, $dry, $identity, $repair, $maxSize
): void {
    $fname = $rfile->filename();
    $hint  = isset($wanted[$fname]);
    if (!$deep && !$hint) {
        return;
    }
    try {
        $report = Report::fromXmlFile($rfile->datastream($maxSize), $maxSize);
    } catch (\Throwable $e) {
        if ($hint) {
            ++$stats['parse_errors'];
            echo "  ! Failed to parse {$fname} ({$where}): {$e->getMessage()}", PHP_EOL;
        }
        return;
    }
    $key = $identity($report);
    if (!isset($suspects[$key])) {
        if ($hint) {
            ++$stats['mismatched'];
            echo "  ! {$fname} ({$where}) contains a different report", PHP_EOL;
        }
        return;
    }
    $s = &$suspects[$key];
    if ($s['status'] === 'repaired') {
        return;
    }
    if ($dry) {
        $s['status'] = 'found';
        $s['detail'] = "{$fname} ({$where})";
        ++$stats['found'];
        return;
    }
    try {
        $repair($s, $report, $fname, $stype);
        $s['status'] = 'repaired';
        $s['detail'] = "{$fname} ({$where})";
        ++$stats['repaired'];
        echo "  + Repaired [{$s['id']}] {$s['fqdn']} {$s['external']} from {$where}: {$fname}", PHP_EOL;
    } catch (\Throwable $e) {
        $s['status'] = 'failed';
        $s['detail'] = $e->getMessage();
        echo "  ! Failed to repair [{$s['id']}] {$s['fqdn']} {$s['external']}: {$e->getMessage()}", PHP_EOL;
    }
};

if (!$source || $source === 'directory') {
    echo PHP_EOL, '=== DIRECTORIES ===', PHP_EOL;
    $m_targets = $moveTargets('directories', SourceAction::FLAG_BASENAME, 'delete', 'move_to:failed');
    foreach ((new DirectoryList())->list() as $dir) {
        $loc  = $dir->toArray()['location'];
        $dirs = array_merge([ $loc ], array_map(function ($t) use ($loc) {
            return $loc . $t . '/';
        }, $m_targets));
        foreach ($dirs as $dpath) {
            if (!is_dir($dpath)) {
                continue;
            }
            try {
                $fs = new \FilesystemIterator($dpath);
            } catch (\Throwable $e) {
                echo "  ! Error accessing directory {$dpath}: {$e->getMessage()}", PHP_EOL;
                continue;
            }
            foreach ($fs as $entry) {
                if (!$entry->isFile()) {
                    continue;
                }
                $bn = $entry->getFilename();
                if (!$deep && !isset($wanted[$bn])) {
                    continue;
                }
                try {
                    $processFile(ReportFile::fromFile($entry->getPathname()), Source::SOURCE_DIRECTORY, $dpath);
                } catch (\Throwable $e) {
                    echo "  ! Error processing {$dpath}{$bn}: {$e->getMessage()}", PHP_EOL;
                }
            }
        }
    }
}

if ((!$source && $core->config('remote_filesystems', null)) || $source === 'remotefs') {
    echo PHP_EOL, '=== REMOTE FILESYSTEMS ===', PHP_EOL;
    try {
        $core->checkDependencies('flyfs,xml,zip');
        foreach ((new RemoteFilesystemList(true))->list() as $fs) {
            $fs_name = $fs->toArray()['name'] ?? '';
            try {
                $f_list = $fs->listFiles();
            } catch (\Throwable $e) {
                echo "  ! Error listing remote filesystem {$fs_name}: {$e->getMessage()}", PHP_EOL;
                continue;
            }
            foreach ($f_list as $attr) {
                $bn = basename($attr->path());
                if (!$deep && !isset($wanted[$bn])) {
                    continue;
                }
                try {
                    $rfile = ReportFile::fromStream($fs->readStream($attr->path()), $bn, $attr->mimeType());
                    $processFile($rfile, Source::SOURCE_REMOTE_FILESYSTEM, $fs_name);
                } catch (\Throwable $e) {
                    echo "  ! Error processing {$attr->path()} ({$fs_name}): {$e->getMessage()}", PHP_EOL;
                }
            }
        }
    } catch (SoftException $e) {
        echo '  ', $e->getMessage(), PHP_EOL;
    }
}

if (!$source || $source === 'email') {
    echo PHP_EOL, '=== MAILBOXES ===', PHP_EOL;
    $mb_list = new MailBoxes();
    if ($mb_list->count() > 0) {
        try {
            $core->checkDependencies('imap-engine|imap,xml,zip');
        } catch (SoftException $e) {
            echo '  ', $e->getMessage(), PHP_EOL;
            $mb_list = null;
        }
        if ($mb_list) {
            $m_targets = $moveTargets('mailboxes', 0, 'mark_seen', 'move_to:failed');
            foreach ($mb_list as $mbox) {
                $boxes = [ $mbox ];
                foreach ($m_targets as $t) {
                    try {
                        $boxes[] = $mbox->childMailbox($t);
                    } catch (\Throwable $e) {
                        echo "  ! Cannot open child mailbox {$t} ({$mbox->name()}): {$e->getMessage()}", PHP_EOL;
                    }
                }
                foreach ($boxes as $box) {
                    try {
                        $msgs = $box->messages(MailBox::SEARCH_ALL, MailBox::ORDER_ASCENT);
                    } catch (\Throwable $e) {
                        echo "  ! Cannot list messages in {$box->folder()} ({$box->name()}): {$e->getMessage()}", PHP_EOL;
                        continue;
                    }
                    foreach ($msgs as $msg) {
                        try {
                            $att = $msg->attachment();
                            $bn  = strval($att->filename());
                        } catch (\Throwable $e) {
                            continue;
                        }
                        if (!$deep && !isset($wanted[$bn])) {
                            continue;
                        }
                        try {
                            $fd = $att->datastream();
                            try {
                                $type = $att->mimeType();
                            } catch (\Throwable $e) {
                                $type = ReportFile::getMimeType($bn, $fd);
                            }
                            $processFile(
                                ReportFile::fromStream($fd, $bn, $type),
                                Source::SOURCE_MAILBOX,
                                "mailbox {$box->name()}:{$box->folder()}"
                            );
                        } catch (\Throwable $e) {
                            echo "  ! Error processing {$bn} ({$box->name()}): {$e->getMessage()}", PHP_EOL;
                        }
                    }
                }
            }
        }
    }
}

// Recounting the corrupted records for each suspect
$st = $db->prepare(
    "SELECT COUNT(*) FROM {$tnrr} AS rr INNER JOIN {$tnrp} AS rp ON rr.report_id = rp.id"
    . " WHERE rp.domain_id = ? AND rp.begin_time = ? AND rp.org = ? AND rp.external_id = ? AND rr.ip LIKE '%?%'"
);
echo PHP_EOL, '=== RESULT ===', PHP_EOL;
$not_found = 0;
$legit     = 0;
foreach ($suspects as &$s) {
    $st->execute([ $s['domain_id'], $s['begin'], $s['org'], $s['external'] ]);
    $bad_now = intval($st->fetchColumn());
    $st->closeCursor();
    switch ($s['status']) {
        case 'repaired':
            if ($bad_now === 0) {
                echo "  + [{$s['id']}] {$s['fqdn']} {$s['external']}: repaired ({$s['detail']})", PHP_EOL;
            } else {
                ++$legit;
                echo "  ~ [{$s['id']}] {$s['fqdn']} {$s['external']}: re-imported but still contains '?' bytes -"
                    . ' probably a false positive (the ? is a part of a real IP address)', PHP_EOL;
            }
            break;
        case 'found':
            echo "  ? [{$s['id']}] {$s['fqdn']} {$s['external']}: source file found: {$s['detail']}", PHP_EOL;
            break;
        case 'failed':
            echo "  ! [{$s['id']}] {$s['fqdn']} {$s['external']}: failed: {$s['detail']}", PHP_EOL;
            break;
        default:
            ++$not_found;
            $hint = '';
            foreach ($s['hints'] as $stype => $fnames) {
                $hint .= ReportLogItem::sourceToString($stype) . ': ' . implode(', ', array_keys($fnames)) . '; ';
            }
            echo "  - [{$s['id']}] {$s['fqdn']} {$s['external']}: source file not found", PHP_EOL;
            if ($hint !== '') {
                echo "      last seen as: {$hint}", PHP_EOL;
            }
            break;
    }
}
unset($s);

echo PHP_EOL;
if ($stats['repaired'] > 0) {
    echo "Repaired: {$stats['repaired']}", PHP_EOL;
}
if ($stats['found'] > 0) {
    echo "Found (dry run, not repaired): {$stats['found']}", PHP_EOL;
}
if ($legit > 0) {
    echo "Probably legitimate '?' bytes: {$legit}", PHP_EOL;
}
if ($not_found > 0) {
    echo "Source file not found: {$not_found}", PHP_EOL;
    echo 'To repair these reports, restore the report files to a configured source', PHP_EOL;
    echo '(or upload them via the web interface) and run this script again.', PHP_EOL;
}
if ($stats['parse_errors'] > 0) {
    echo "Files failed to parse: {$stats['parse_errors']}", PHP_EOL;
}
if ($stats['mismatched'] > 0) {
    echo "Files containing a different report: {$stats['mismatched']}", PHP_EOL;
}
if ($uploaded > 0) {
    echo "Note: {$uploaded} report(s) were originally uploaded via the web interface", PHP_EOL;
    echo 'and cannot be recovered automatically.', PHP_EOL;
}
