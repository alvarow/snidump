<?php
require_once("util.inc");
require_once("config.inc");
require_once("functions.inc");
require_once("service-utils.inc");

function snidump_install() {
    if (!is_dir('/var/log/snidump')) {
        mkdir('/var/log/snidump', 0750, true);
        chown('/var/log/snidump', 'root');
        chgrp('/var/log/snidump', 'wheel');
    }
}

function snidump_deinstall() {
    mwexec('/usr/sbin/service snidump stop 2>/dev/null');
    // Remove snidump_* lines from rc.conf.local
    snidump_remove_rcconf_lines();
    // Remove newsyslog config
    @unlink('/etc/newsyslog.conf.d/snidump');
}

function snidump_remove_rcconf_lines() {
    $path = '/etc/rc.conf.local';
    if (!file_exists($path)) {
        return;
    }
    $lines = file($path, FILE_IGNORE_NEW_LINES);
    $filtered = array_filter($lines, function($line) {
        return !preg_match('/^snidump_/', $line);
    });
    file_put_contents($path, implode("\n", array_values($filtered)) . "\n");
}

function snidump_build_flags($cfg) {
    $flags = '';
    if (!empty($cfg['quiet']))     $flags .= ' -q';
    if (!empty($cfg['json']))      $flags .= ' -j';
    if (empty($cfg['json']) && !empty($cfg['timestamp'])) $flags .= ' -t';
    if (!empty($cfg['count']) && intval($cfg['count']) > 0) {
        $flags .= ' -c ' . intval($cfg['count']);
    }
    return ltrim($flags);
}

function snidump_write_newsyslog($cfg) {
    $logfile = $cfg['logfile'] ?: '/var/log/snidump/hosts.jsonl';
    $count   = intval($cfg['log_rotate_count'] ?: 30);
    $when    = $cfg['log_rotate_when'] ?: 'daily';

    switch ($when) {
        case 'weekly':
            $size     = '*';
            $interval = '@W0';
            break;
        case 'bysize':
            $size     = intval($cfg['log_rotate_size_kb'] ?: 512);
            $interval = '*';
            break;
        default: // daily
            $size     = '*';
            $interval = '@T00';
            break;
    }

    $line = "{$logfile}\troot:wheel\t640\t{$count}\t{$size}\t{$interval}\tCZ\n";
    @mkdir('/etc/newsyslog.conf.d', 0755, true);
    file_put_contents('/etc/newsyslog.conf.d/snidump', $line);
}

function sync_package_snidump() {
    $cfg = config_get_path('installedpackages/snidump/config/0', []);

    $realif = convert_friendly_interface_to_real_interface_name($cfg['interface'] ?? 'lan');
    $binary  = ($cfg['interface_type'] === 'tunnel') ? 'snidump_noether' : 'snidump';
    $logfile = $cfg['logfile'] ?: '/var/log/snidump/hosts.jsonl';
    $flags   = snidump_build_flags($cfg);

    // Sanitize values for shell safety before interpolating into rc.conf.local
    $realif_safe = preg_replace('/[^a-zA-Z0-9\/_.\\-]/', '', $realif);
    $binary_safe = preg_replace('/[^a-zA-Z0-9\/_.\\-]/', '', $binary);
    $logfile_safe = preg_replace('/[^a-zA-Z0-9\/_.\\-]/', '', $logfile);
    // flags is safely assembled from controlled values; no sanitization needed
    // BPF filter is handled via a separate rc variable to avoid word-splitting
    $bpf_raw = str_replace(['\\', '"', '$', '`'], ['\\\\', '\\"', '\\$', '\\`'], trim($cfg['bpf'] ?? ''));

    // Ensure log directory exists
    if (!is_dir(dirname($logfile))) {
        mkdir(dirname($logfile), 0750, true);
    }

    // Write rc.conf.local stanza (replaces any existing snidump_* lines)
    snidump_remove_rcconf_lines();
    $stanza = implode("\n", [
        "snidump_enable=\"YES\"",
        "snidump_interface=\"{$realif_safe}\"",
        "snidump_binary=\"{$binary_safe}\"",
        "snidump_flags=\"{$flags}\"",
        "snidump_logfile=\"{$logfile_safe}\"",
        "snidump_bpf=\"{$bpf_raw}\"",
    ]) . "\n";
    file_put_contents('/etc/rc.conf.local', $stanza, FILE_APPEND);

    // Write newsyslog config
    snidump_write_newsyslog($cfg);

    // Start or stop service
    if (!empty($cfg['enable'])) {
        if (is_service_running('snidump')) {
            mwexec('/usr/sbin/service snidump restart');
        } else {
            mwexec('/usr/sbin/service snidump start');
        }
    } else {
        mwexec('/usr/sbin/service snidump stop 2>/dev/null');
        // Remove enable line so service does not start at next boot
        snidump_remove_rcconf_lines();
        file_put_contents('/etc/rc.conf.local',
            "snidump_enable=\"NO\"\n", FILE_APPEND);
    }
}

function validate_form_snidump($post, &$input_errors) {
    if (empty($post['interface'])) {
        $input_errors[] = 'An interface must be selected.';
    }

    if (!empty($post['bpf'])) {
        $tmpfile = tempnam('/tmp', 'snidump_bpf_');
        file_put_contents($tmpfile, $post['bpf']);
        exec('/usr/sbin/tcpdump -d -F ' . escapeshellarg($tmpfile) . ' 2>&1', $out, $ret);
        @unlink($tmpfile);
        if ($ret !== 0) {
            $input_errors[] = 'Invalid BPF filter: ' . htmlspecialchars(implode(' ', $out));
        }
    }

    if (!empty($post['count']) && (!ctype_digit($post['count']) || intval($post['count']) < 1)) {
        $input_errors[] = '"Stop after N matches" must be a positive integer.';
    }

    if (!empty($post['logfile']) && $post['logfile'][0] !== '/') {
        $input_errors[] = 'Log file path must be an absolute path (start with /).';
    }

    if (!empty($post['log_rotate_count']) &&
        (!ctype_digit($post['log_rotate_count']) || intval($post['log_rotate_count']) < 1)) {
        $input_errors[] = '"Keep N rotated files" must be a positive integer.';
    }

    if ($post['log_rotate_when'] === 'bysize') {
        $kb = $post['log_rotate_size_kb'] ?? '';
        if (!ctype_digit($kb) || intval($kb) < 1) {
            $input_errors[] = '"Size limit (KB)" must be a positive integer when rotating by size.';
        }
    }
}
