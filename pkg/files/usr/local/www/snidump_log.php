<?php
##|+PRIV
##|*IDENT=page-diagnostics-snidump
##|*NAME=Diagnostics: snidump
##|*DESCR=Allow access to the 'Diagnostics: snidump' page.
##|*MATCH=snidump_log.php*
##|-PRIV

require_once('guiconfig.inc');
require_once('service-utils.inc');

$cfg = config_get_path('installedpackages/snidump/config/0', []);
$logfile  = $cfg['logfile'] ?: '/var/log/snidump/hosts.jsonl';
$use_json = !empty($cfg['json']);

$valid_limits = [50, 200, 500];
$limit = in_array((int)$_GET['limit'], $valid_limits) ? (int)$_GET['limit'] : 200;
$autorefresh = isset($_GET['autorefresh']) && $_GET['autorefresh'] === '1';

// Handle action buttons
$savemsg = '';
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!empty($_POST['start'])) {
        mwexec('/usr/sbin/service snidump start');
        $savemsg = 'Service started.';
    } elseif (!empty($_POST['stop'])) {
        mwexec('/usr/sbin/service snidump stop');
        $savemsg = 'Service stopped.';
    } elseif (!empty($_POST['restart'])) {
        mwexec('/usr/sbin/service snidump restart');
        $savemsg = 'Service restarted.';
    } elseif (!empty($_POST['clear_log'])) {
        file_put_contents($logfile, '');
        $savemsg = 'Log cleared.';
    }
}

$running = is_service_running('snidump');
$status_label = $running ? 'Running' : 'Stopped';
$status_class = $running ? 'success' : 'danger';

// Read last N lines of log
$log_lines = [];
if (file_exists($logfile)) {
    // Use tail to avoid reading entire file
    exec('/usr/bin/tail -n ' . intval($limit) . ' ' . escapeshellarg($logfile), $log_lines);
}

$pgtitle = [gettext('Diagnostics'), gettext('snidump')];
include('head.inc');

if ($autorefresh): ?>
<meta http-equiv="refresh" content="10;url=snidump_log.php?limit=<?=htmlspecialchars($limit)?>&autorefresh=1">
<?php endif;

if ($savemsg): print_info_box($savemsg, 'success'); endif;
?>

<div class="panel panel-default">
	<div class="panel-heading"><h2 class="panel-title"><?=gettext('Service Status')?></h2></div>
	<div class="panel-body">
		<span class="label label-<?=$status_class?>"><?=htmlspecialchars($status_label)?></span>
		<?php if (!empty($cfg['interface'])): ?>
		&nbsp; Interface: <strong><?=htmlspecialchars($cfg['interface'])?></strong>
		&nbsp; Binary: <strong><?=htmlspecialchars(($cfg['interface_type'] === 'tunnel') ? 'snidump_noether' : 'snidump')?></strong>
		<?php endif; ?>
		<form method="post" style="display:inline; margin-left:1em;">
			<button type="submit" name="start"   class="btn btn-xs btn-success">Start</button>
			<button type="submit" name="stop"    class="btn btn-xs btn-danger">Stop</button>
			<button type="submit" name="restart" class="btn btn-xs btn-warning">Restart</button>
		</form>
		<a href="/pkg_edit.php?xml=snidump.xml&id=0" class="btn btn-xs btn-default" style="margin-left:0.5em;">Settings</a>
	</div>
</div>

<div class="panel panel-default">
	<div class="panel-heading">
		<h2 class="panel-title">
			<?=gettext('Hostname Log')?>
			<span style="font-size:0.85em; font-weight:normal; margin-left:1em;">
				Show last:
				<?php foreach ($valid_limits as $l): ?>
					<?php if ($l === $limit): ?><strong><?=$l?></strong><?php else: ?>
					<a href="snidump_log.php?limit=<?=$l?><?=$autorefresh?'&autorefresh=1':''?>"><?=$l?></a>
					<?php endif; ?>&nbsp;
				<?php endforeach; ?>
				&nbsp;|&nbsp;
				<?php if ($autorefresh): ?>
					<a href="snidump_log.php?limit=<?=$limit?>">Stop auto-refresh</a>
				<?php else: ?>
					<a href="snidump_log.php?limit=<?=$limit?>&autorefresh=1">Auto-refresh (10s)</a>
				<?php endif; ?>
			</span>
		</h2>
	</div>
	<div class="panel-body">
		<?php if (empty($log_lines)): ?>
			<p class="text-muted"><?=gettext('No log data — service has not produced output yet.')?></p>
		<?php elseif ($use_json): ?>
		<div class="table-responsive">
			<table class="table table-striped table-hover table-condensed sortable-theme-bootstrap" data-sortable>
				<thead><tr>
					<th><?=gettext('Time')?></th>
					<th><?=gettext('Proto')?></th>
					<th><?=gettext('Src')?></th>
					<th><?=gettext('Dst')?></th>
					<th><?=gettext('Host')?></th>
				</tr></thead>
				<tbody>
				<?php foreach ($log_lines as $line):
					$obj = json_decode($line, true);
					if (!$obj) continue; ?>
				<tr>
					<td><?=htmlspecialchars($obj['time'] ?? '')?></td>
					<td><?=htmlspecialchars($obj['proto'] ?? '')?></td>
					<td><?=htmlspecialchars($obj['src'] ?? '')?></td>
					<td><?=htmlspecialchars($obj['dst'] ?? '')?></td>
					<td><?=htmlspecialchars($obj['host'] ?? '')?></td>
				</tr>
				<?php endforeach; ?>
				</tbody>
			</table>
		</div>
		<?php else: ?>
		<pre><?php foreach ($log_lines as $line) echo htmlspecialchars($line) . "\n"; ?></pre>
		<?php endif; ?>

		<?php if (!empty($log_lines)): ?>
		<form method="post" onsubmit="return confirm('Clear the log file?');">
			<button type="submit" name="clear_log" class="btn btn-xs btn-danger">Clear log</button>
		</form>
		<?php endif; ?>
	</div>
</div>

<?php include('foot.inc'); ?>
