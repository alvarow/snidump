# pfSense Package Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Package snidump as an installable pfSense pkg with a web UI for configuration and log viewing.

**Architecture:** Two PRs on `feature/pfsense-package`. PR 1 delivers the FreeBSD pkg infrastructure (port Makefile, rc.d update, pre-built binaries). PR 2 delivers the PHP web UI (XML-driven settings form via `snidump.xml`, `snidump.inc` business logic, `snidump_log.php` custom log viewer). Settings form is XML-driven using pfSense's built-in `pkg_edit.php`; only the log viewer is a custom PHP page.

**Tech Stack:** FreeBSD pkg(8), pfSense XML package framework, PHP 8, Bootstrap 3 (pfSense UI), sh (rc.d)

**Spec:** `docs/superpowers/specs/2026-08-31-pfsense-package-design.md`

## Global Constraints

- Target: pfSense CE 2.8.x / pfSense Plus 24.x (FreeBSD 15.0 amd64)
- Binaries: pre-built, no compiler on appliance — build on a FreeBSD 15 amd64 machine
- No compiler on pfSense — `pkg add` installs pre-staged binaries only
- pfSense never write to `/etc/rc.conf` directly — use `/etc/rc.conf.local`
- Log rotation config goes in `/etc/newsyslog.conf.d/` (survives pfSense upgrades)
- PHP: use `config_get_path()` / `config_set_path()` API (not direct `$config` array access)
- Service control: `mwexec('/usr/sbin/service snidump start|stop|restart')`
- pfSense interface values in XML are friendly names (e.g. "wan", "opt1"); convert with `convert_friendly_interface_to_real_interface_name()` before writing rc.conf.local
- Test access: `ssh alvaro@pfsense`

---

## File Map

| File | Action | Purpose |
|------|--------|---------|
| `contrib/snidump.rc` | Modify | Add `snidump_binary` variable |
| `pkg/Makefile` | Create | FreeBSD port Makefile (NO_BUILD, NO_FETCH) |
| `pkg/pkg-descr` | Create | One-paragraph pkg description |
| `pkg/pkg-plist` | Create | Installed file list (updated in Task 9) |
| `pkg/snidump.xml` | Create | pfSense package GUI definition |
| `pkg/files/usr/local/bin/snidump` | Create | Symlink → `builds/amd64/freebsd-15/snidump` |
| `pkg/files/usr/local/bin/snidump_noether` | Create | Symlink → `builds/amd64/freebsd-15/snidump_noether` |
| `pkg/files/usr/local/etc/rc.d/snidump` | Create | Copy of updated contrib/snidump.rc |
| `pkg/files/usr/local/etc/newsyslog.conf.d/snidump` | Create | Static default log rotation |
| `pkg/files/usr/local/pkg/snidump.inc` | Create | PHP: install/deinstall/resync/validate hooks |
| `pkg/files/usr/local/www/snidump_log.php` | Create | Custom log/status viewer page |
| `builds/amd64/freebsd-15/snidump` | Create | Pre-built binary (compile step) |
| `builds/amd64/freebsd-15/snidump_noether` | Create | Pre-built binary (compile step) |
| `Makefile` | Modify | Add `pkg-build` target |

---

## Task 1: Feature branch + rc.d script update

**Files:**
- Modify: `contrib/snidump.rc`
- Create: `pkg/files/usr/local/etc/rc.d/snidump` (copy)

**Interfaces:**
- Produces: `snidump_binary` rc variable; rc.d script accepts `snidump_noether` as binary name

- [ ] **Step 1: Create the feature branch**

```bash
git checkout -b feature/pfsense-package
```

- [ ] **Step 2: Add `snidump_binary` variable to contrib/snidump.rc**

In `contrib/snidump.rc`, after the existing `: ${snidump_pidfile:=...}` line, add:

```sh
: ${snidump_binary:="snidump"}
```

Change the `command_args` line from:
```sh
command_args="-p ${snidump_pidfile} -r \
    -o ${snidump_logfile} \
    /usr/local/bin/snidump ${snidump_flags} -i ${snidump_interface}"
```
to:
```sh
command_args="-p ${snidump_pidfile} -r \
    -o ${snidump_logfile} \
    /usr/local/bin/${snidump_binary} ${snidump_flags} -i ${snidump_interface}"
```

- [ ] **Step 3: Test rc.d script on pfSense**

```bash
scp contrib/snidump.rc alvaro@pfsense:/tmp/snidump.rc
ssh alvaro@pfsense 'sudo cp /tmp/snidump.rc /usr/local/etc/rc.d/snidump && sudo chmod +x /usr/local/etc/rc.d/snidump'
# Set snidump_binary in rc.conf.local and verify service starts with correct binary
ssh alvaro@pfsense 'grep snidump /etc/rc.conf.local'
ssh alvaro@pfsense 'sudo service snidump status'
```

Expected: service reports running with the binary specified in `snidump_binary`.

- [ ] **Step 4: Create pkg/files rc.d copy**

```bash
mkdir -p pkg/files/usr/local/etc/rc.d
cp contrib/snidump.rc pkg/files/usr/local/etc/rc.d/snidump
chmod +x pkg/files/usr/local/etc/rc.d/snidump
```

- [ ] **Step 5: Commit**

```bash
git add contrib/snidump.rc pkg/files/usr/local/etc/rc.d/snidump
git commit -m "feat(pkg): add snidump_binary variable to rc.d script"
```

---

## Task 2: pkg scaffold (Makefile, pkg-descr, newsyslog, root Makefile target)

**Files:**
- Create: `pkg/Makefile`
- Create: `pkg/pkg-descr`
- Create: `pkg/files/usr/local/etc/newsyslog.conf.d/snidump`
- Modify: `Makefile` (root)

**Interfaces:**
- Produces: `make pkg-build` target in root Makefile; `pkg/Makefile` buildable with `make package`

- [ ] **Step 1: Create pkg/Makefile**

```makefile
# pkg/Makefile
PORTNAME=	pfSense-pkg-snidump
PORTVERSION=	0.1.0
CATEGORIES=	security
MAINTAINER=	alvaro@example.com
COMMENT=	Extracts TLS SNI and HTTP Host headers from live traffic

LICENSE=	MIT

RUN_DEPENDS=	${LOCALBASE}/lib/libpcre2-8.so:devel/pcre2

NO_BUILD=	yes
NO_FETCH=	yes

PLIST_FILES=	\
	usr/local/bin/snidump \
	usr/local/bin/snidump_noether \
	usr/local/etc/rc.d/snidump \
	"@dir usr/local/etc/newsyslog.conf.d" \
	usr/local/etc/newsyslog.conf.d/snidump

do-install:
	${INSTALL_PROGRAM} ${WRKSRC}/../files/usr/local/bin/snidump \
		${STAGEDIR}${PREFIX}/bin/snidump
	${INSTALL_PROGRAM} ${WRKSRC}/../files/usr/local/bin/snidump_noether \
		${STAGEDIR}${PREFIX}/bin/snidump_noether
	${INSTALL_SCRIPT} ${WRKSRC}/../files/usr/local/etc/rc.d/snidump \
		${STAGEDIR}${PREFIX}/etc/rc.d/snidump
	${INSTALL_DATA} ${WRKSRC}/../files/usr/local/etc/newsyslog.conf.d/snidump \
		${STAGEDIR}${PREFIX}/etc/newsyslog.conf.d/snidump

post-install:
	@${INSTALL} -d -m 750 ${STAGEDIR}/var/log/snidump

.include <bsd.port.mk>
```

- [ ] **Step 2: Create pkg/pkg-descr**

```
snidump extracts the Server Name Indication (SNI) field from TLS ClientHello
messages and the Host header from HTTP/1.1 requests. It captures from a live
network interface or a PCAP file and outputs plain text, timestamped lines,
or JSON (one object per line). Supports IPv4 and IPv6.

WWW: https://github.com/alvarow/snidump
```

- [ ] **Step 3: Create the default newsyslog config**

```bash
mkdir -p pkg/files/usr/local/etc/newsyslog.conf.d
cat > pkg/files/usr/local/etc/newsyslog.conf.d/snidump << 'EOF'
/var/log/snidump/hosts.jsonl  root:wheel  640  30  *  @T00  CZ
EOF
```

- [ ] **Step 4: Add pkg-build target to root Makefile**

In the root `Makefile`, after the `uninstall` target, add:

```makefile
# Build the pfSense .pkg. Requires a FreeBSD 15 amd64 build environment.
# Binaries must already be in builds/amd64/freebsd-15/ before running this.
pkg-build:
	@test -f builds/amd64/freebsd-15/snidump || \
	  { echo "[ERROR] builds/amd64/freebsd-15/snidump not found."; \
	    echo "        Compile on a FreeBSD 15 amd64 machine first."; exit 1; }
	cp builds/amd64/freebsd-15/snidump         pkg/files/usr/local/bin/snidump
	cp builds/amd64/freebsd-15/snidump_noether pkg/files/usr/local/bin/snidump_noether
	cp contrib/snidump.rc pkg/files/usr/local/etc/rc.d/snidump
	chmod +x pkg/files/usr/local/etc/rc.d/snidump
	cd pkg && make package
	@echo ""
	@echo "Package: pkg/work/pkg/$(PORTNAME)-$(PORTVERSION).pkg"
```

- [ ] **Step 5: Create builds/amd64/freebsd-15/ directory with a README**

```bash
mkdir -p builds/amd64/freebsd-15
cat > builds/amd64/freebsd-15/README.md << 'EOF'
# FreeBSD 15 amd64 binaries (pfSense CE 2.8.x / pfSense Plus 24.x)

Build on a FreeBSD 15 amd64 machine:

    make CC=clang CFLAGS="-I/usr/local/include" LDFLAGS="-L/usr/local/lib"
    cp bin/snidump bin/snidump_noether builds/amd64/freebsd-15/

Then from the repo root:

    make pkg-build
EOF
```

- [ ] **Step 6: Commit**

```bash
git add pkg/Makefile pkg/pkg-descr \
    pkg/files/usr/local/etc/newsyslog.conf.d/snidump \
    builds/amd64/freebsd-15/README.md Makefile
git commit -m "feat(pkg): add FreeBSD port scaffold and pkg-build Makefile target"
```

---

## Task 3: Build FreeBSD 15 amd64 binaries

**Files:**
- Create: `builds/amd64/freebsd-15/snidump`
- Create: `builds/amd64/freebsd-15/snidump_noether`

**Interfaces:**
- Produces: binaries consumed by `make pkg-build`

**Prerequisite:** A FreeBSD 15 amd64 machine, VM, or jail with `clang`, `libpcap` (base), and `pcre2` (`pkg install pcre2`).

- [ ] **Step 1: Compile on a FreeBSD 15 amd64 build machine**

```bash
# On the FreeBSD 15 build machine, in the snidump repo:
make CC=clang CFLAGS="-I/usr/local/include" LDFLAGS="-L/usr/local/lib"
```

Expected: `bin/snidump` and `bin/snidump_noether` produced without warnings.

- [ ] **Step 2: Verify the binaries are dynamically linked against the right libraries**

```bash
ldd bin/snidump
# Must show: libpcap.so, libpcre2-8.so — both present on pfSense
file bin/snidump
# Must show: ELF 64-bit, x86-64, dynamically linked
```

- [ ] **Step 3: Copy binaries into builds/amd64/freebsd-15/**

```bash
cp bin/snidump bin/snidump_noether builds/amd64/freebsd-15/
```

- [ ] **Step 4: Quick smoke test on pfSense**

```bash
scp builds/amd64/freebsd-15/snidump alvaro@pfsense:/tmp/snidump_test
ssh alvaro@pfsense '/tmp/snidump_test -h'
```

Expected: usage message printed (not a dynamic linker error).

- [ ] **Step 5: Commit**

```bash
git add builds/amd64/freebsd-15/snidump builds/amd64/freebsd-15/snidump_noether
git commit -m "feat(pkg): add FreeBSD 15 amd64 pre-built binaries"
```

---

## Task 4: pkg-plist and first pkg install on pfSense (PR 1)

**Files:**
- Create: `pkg/pkg-plist`
- Create: `pkg/files/usr/local/bin/` (binaries staged by pkg-build)

**Interfaces:**
- Produces: installable `.pkg` file; `pkg add` works on pfSense

- [ ] **Step 1: Create pkg/pkg-plist**

```
bin/snidump
bin/snidump_noether
etc/rc.d/snidump
@dir etc/newsyslog.conf.d
etc/newsyslog.conf.d/snidump
@dir(root,wheel,0750) /var/log/snidump
```

- [ ] **Step 2: Stage binaries and build the package**

On the FreeBSD 15 build machine (or after copying binaries locally):

```bash
make pkg-build
```

Expected: `pkg/work/pkg/pfSense-pkg-snidump-0.1.0.pkg` produced.

- [ ] **Step 3: Verify package metadata**

```bash
pkg info -F pkg/work/pkg/pfSense-pkg-snidump-0.1.0.pkg
# Must show: name, version, origin, dependencies (pcre2)
pkg info -lF pkg/work/pkg/pfSense-pkg-snidump-0.1.0.pkg
# Must list all files in plist
```

- [ ] **Step 4: Install on pfSense and verify**

```bash
scp pkg/work/pkg/pfSense-pkg-snidump-0.1.0.pkg alvaro@pfsense:/tmp/
ssh alvaro@pfsense 'sudo pkg add /tmp/pfSense-pkg-snidump-0.1.0.pkg'
ssh alvaro@pfsense 'pkg info pfSense-pkg-snidump'
ssh alvaro@pfsense 'ls -la /usr/local/bin/snidump /usr/local/bin/snidump_noether'
ssh alvaro@pfsense 'ls -la /usr/local/etc/rc.d/snidump'
ssh alvaro@pfsense 'ls -la /var/log/snidump/'
```

Expected: all files present, log directory exists.

- [ ] **Step 5: Test service start via rc.d**

```bash
ssh alvaro@pfsense 'echo snidump_enable=\"YES\" >> /etc/rc.conf.local'
ssh alvaro@pfsense 'echo snidump_interface=\"em0\" >> /etc/rc.conf.local'
ssh alvaro@pfsense 'echo snidump_flags=\"-q -j\" >> /etc/rc.conf.local'
ssh alvaro@pfsense 'echo snidump_logfile=\"/var/log/snidump/hosts.jsonl\" >> /etc/rc.conf.local'
ssh alvaro@pfsense 'sudo service snidump start && sleep 2 && sudo service snidump status'
```

Expected: service reports running.

- [ ] **Step 6: Clean up test install**

```bash
ssh alvaro@pfsense 'sudo pkg remove pfSense-pkg-snidump'
ssh alvaro@pfsense 'sudo service snidump stop'
```

- [ ] **Step 7: Commit and open PR 1**

```bash
git add pkg/pkg-plist
git commit -m "feat(pkg): add pkg-plist; PR 1 complete — pkg infrastructure"
# Open PR targeting master from feature/pfsense-package
```

---

## Task 5: snidump.xml — pfSense package definition

**Files:**
- Create: `pkg/snidump.xml`

**Interfaces:**
- Produces: XML consumed by pfSense's `pkg_edit.php` to render the settings form; calls `validate_form_snidump()` and `sync_package_snidump()` from `snidump.inc`

- [ ] **Step 1: Create pkg/snidump.xml**

```xml
<?xml version="1.0" encoding="utf-8" ?>
<packagegui>
	<title>Diagnostics/snidump</title>
	<name>snidump</name>
	<version>0.1.0</version>
	<include_file>/usr/local/pkg/snidump.inc</include_file>
	<menu>
		<name>snidump</name>
		<tooltiptext>View snidump hostname log and service status</tooltiptext>
		<section>Diagnostics</section>
		<url>/snidump_log.php</url>
	</menu>
	<service>
		<name>snidump</name>
		<rcfile>snidump</rcfile>
		<executable>snidump</executable>
		<description>TLS SNI / HTTP Host extractor</description>
	</service>
	<tabs>
		<tab>
			<text>Settings</text>
			<url>/pkg_edit.php?xml=snidump.xml&amp;id=0</url>
			<active/>
		</tab>
		<tab>
			<text>Log Viewer</text>
			<url>/snidump_log.php</url>
		</tab>
	</tabs>
	<fields>
		<field>
			<name>Service</name>
			<type>listtopic</type>
		</field>
		<field>
			<fielddescr>Enable</fielddescr>
			<fieldname>enable</fieldname>
			<type>checkbox</type>
			<description>Start snidump at boot and apply settings</description>
		</field>
		<field>
			<name>Capture</name>
			<type>listtopic</type>
		</field>
		<field>
			<fielddescr>Interface</fielddescr>
			<fieldname>interface</fieldname>
			<type>interfaces_selection</type>
			<hideinterfaceregex>loopback</hideinterfaceregex>
			<description>Network interface to capture on</description>
			<required/>
		</field>
		<field>
			<fielddescr>Interface Type</fielddescr>
			<fieldname>interface_type</fieldname>
			<type>select</type>
			<options>
				<option><name>Ethernet / Wi-Fi (use snidump)</name><value>ethernet</value></option>
				<option><name>TUN / VPN / Tunnel (use snidump_noether)</name><value>tunnel</value></option>
			</options>
			<default_value>ethernet</default_value>
			<description><![CDATA[Ethernet/Wi-Fi interfaces have a 14-byte link-layer header;
				TUN/VPN/tunnel interfaces (tun0, gif0, gre0) deliver raw IP frames with no header.
				Choose <em>TUN / VPN / Tunnel</em> for WireGuard, OpenVPN TUN, or FreeBSD gif/gre interfaces.]]>
			</description>
		</field>
		<field>
			<fielddescr>BPF Filter</fielddescr>
			<fieldname>bpf</fieldname>
			<type>input</type>
			<size>60</size>
			<description><![CDATA[Custom BPF capture filter. Leave empty to use the built-in default:
				<code>(ip or ip6) and tcp and (tcp[tcpflags] &amp; tcp-push == tcp-push) and (dst port 80 or dst port 443)</code>]]>
			</description>
		</field>
		<field>
			<name>Output</name>
			<type>listtopic</type>
		</field>
		<field>
			<fielddescr>Quiet mode (-q)</fielddescr>
			<fieldname>quiet</fieldname>
			<type>checkbox</type>
			<description>Suppress informational startup lines</description>
		</field>
		<field>
			<fielddescr>JSON output (-j)</fielddescr>
			<fieldname>json</fieldname>
			<type>checkbox</type>
			<description>Output one JSON object per matched hostname (includes timestamp)</description>
		</field>
		<field>
			<fielddescr>Timestamps (-t)</fielddescr>
			<fieldname>timestamp</fieldname>
			<type>checkbox</type>
			<description>Prefix each hostname line with a UTC timestamp (ignored when JSON is enabled)</description>
		</field>
		<field>
			<fielddescr>Stop after N matches (-c)</fielddescr>
			<fieldname>count</fieldname>
			<type>input</type>
			<size>8</size>
			<description>Stop capturing after this many hostname matches. Leave empty for unlimited.</description>
		</field>
		<field>
			<name>Logging</name>
			<type>listtopic</type>
		</field>
		<field>
			<fielddescr>Log file path</fielddescr>
			<fieldname>logfile</fieldname>
			<type>input</type>
			<size>60</size>
			<default_value>/var/log/snidump/hosts.jsonl</default_value>
			<description>Absolute path to the output log file</description>
		</field>
		<field>
			<fielddescr>Keep N rotated files</fielddescr>
			<fieldname>log_rotate_count</fieldname>
			<type>input</type>
			<size>8</size>
			<default_value>30</default_value>
			<description>Number of rotated log files to retain</description>
		</field>
		<field>
			<fielddescr>Rotate</fielddescr>
			<fieldname>log_rotate_when</fieldname>
			<type>select</type>
			<options>
				<option><name>Daily (midnight)</name><value>daily</value></option>
				<option><name>Weekly (Sunday midnight)</name><value>weekly</value></option>
				<option><name>By size — enter KB below</name><value>bysize</value></option>
			</options>
			<default_value>daily</default_value>
			<description>When to rotate the log file</description>
		</field>
		<field>
			<fielddescr>Size limit (KB)</fielddescr>
			<fieldname>log_rotate_size_kb</fieldname>
			<type>input</type>
			<size>8</size>
			<description>Maximum log file size in KB before rotation. Only used when "By size" is selected above.</description>
		</field>
	</fields>
	<custom_php_validation_command>validate_form_snidump($_POST, $input_errors);</custom_php_validation_command>
	<custom_php_resync_config_command>sync_package_snidump();</custom_php_resync_config_command>
	<custom_php_install_command>snidump_install();</custom_php_install_command>
	<custom_php_deinstall_command>snidump_deinstall();</custom_php_deinstall_command>
</packagegui>
```

Note: the `log_rotate_size_kb` field is a separate input to avoid needing JavaScript for a conditional field. The `.inc` validation ignores it unless `log_rotate_when == "bysize"`.

- [ ] **Step 2: Copy snidump.xml to pfSense and verify form renders**

```bash
scp pkg/snidump.xml alvaro@pfsense:/usr/local/pkg/snidump.xml
# In browser: https://pfsense/pkg_edit.php?xml=snidump.xml&id=0
# Expected: form renders with all fields, no PHP errors
```

- [ ] **Step 3: Commit**

```bash
git add pkg/snidump.xml
git commit -m "feat(pkg): add snidump.xml pfSense package GUI definition"
```

---

## Task 6: snidump.inc — PHP business logic

**Files:**
- Create: `pkg/files/usr/local/pkg/snidump.inc`

**Interfaces:**
- Consumes: `config_get_path('installedpackages/snidump/config/0')` for settings; `convert_friendly_interface_to_real_interface_name()` from pfSense functions.inc
- Produces: `snidump_install()`, `snidump_deinstall()`, `sync_package_snidump()`, `validate_form_snidump()` — called by pfSense via snidump.xml hooks

- [ ] **Step 1: Create pkg/files/usr/local/pkg/snidump.inc**

```php
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
    if (!empty($cfg['bpf'])) {
        // BPF filter is validated before save; pass it via -f flag
        $flags .= ' -f ' . escapeshellarg(trim($cfg['bpf']));
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

    // Ensure log directory exists
    if (!is_dir(dirname($logfile))) {
        mkdir(dirname($logfile), 0750, true);
    }

    // Write rc.conf.local stanza (replaces any existing snidump_* lines)
    snidump_remove_rcconf_lines();
    $stanza = implode("\n", [
        "snidump_enable=\"YES\"",
        "snidump_interface=\"{$realif}\"",
        "snidump_binary=\"{$binary}\"",
        "snidump_flags=\"{$flags}\"",
        "snidump_logfile=\"{$logfile}\"",
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
        exec('/usr/sbin/tcpdump -d -r /dev/null -F ' . escapeshellarg($tmpfile) . ' 2>&1', $out, $ret);
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
```

- [ ] **Step 2: Deploy to pfSense and test each hook manually**

```bash
mkdir -p pkg/files/usr/local/pkg
# (file already written above)
scp pkg/files/usr/local/pkg/snidump.inc alvaro@pfsense:/usr/local/pkg/snidump.inc

# Test install hook
ssh alvaro@pfsense 'php -r "require_once(\"/usr/local/pkg/snidump.inc\"); snidump_install();"'
ssh alvaro@pfsense 'ls -la /var/log/snidump/'
# Expected: directory exists, mode 750, owned root:wheel

# Test sync with sample config (set via config.xml or hardcode a test call):
# Visit https://pfsense/pkg_edit.php?xml=snidump.xml&id=0
# Fill in interface, enable checkbox, save
# Expected: /etc/rc.conf.local has snidump_* lines, service starts, /etc/newsyslog.conf.d/snidump written
ssh alvaro@pfsense 'grep snidump /etc/rc.conf.local'
ssh alvaro@pfsense 'cat /etc/newsyslog.conf.d/snidump'
ssh alvaro@pfsense 'sudo service snidump status'
```

- [ ] **Step 3: Test validation rejects bad inputs**

In browser at `pkg_edit.php?xml=snidump.xml&id=0`:
- Enter `NOT A BPF` in BPF filter → save → expected: red error "Invalid BPF filter"
- Enter `abc` in "Stop after N matches" → save → expected: red error
- Enter `relative/path` in log file → save → expected: red error

- [ ] **Step 4: Commit**

```bash
git add pkg/files/usr/local/pkg/snidump.inc
git commit -m "feat(pkg): add snidump.inc PHP hooks (install/deinstall/resync/validate)"
```

---

## Task 7: snidump_log.php — log/status viewer

**Files:**
- Create: `pkg/files/usr/local/www/snidump_log.php`

**Interfaces:**
- Consumes: `config_get_path('installedpackages/snidump/config/0')`, `is_service_running('snidump')`, log file at configured path
- Produces: HTML page at `/snidump_log.php` accessible from pfSense web UI

- [ ] **Step 1: Create pkg/files/usr/local/www/snidump_log.php**

```php
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
```

- [ ] **Step 2: Deploy to pfSense and verify page renders**

```bash
mkdir -p pkg/files/usr/local/www
scp pkg/files/usr/local/www/snidump_log.php alvaro@pfsense:/usr/local/www/snidump_log.php
# In browser: https://pfsense/snidump_log.php
```

Expected: page loads, shows service status badge, Start/Stop/Restart buttons work, log table populates after service produces output.

- [ ] **Step 3: Verify auto-refresh**

In browser: click "Auto-refresh (10s)". Expected: page refreshes every 10 seconds, URL has `autorefresh=1`.

- [ ] **Step 4: Verify Clear log**

Click "Clear log" button, confirm dialog appears, on confirm the log file is truncated and the table shows "No log data".

- [ ] **Step 5: Verify menu link**

In pfSense web UI: `Diagnostics` menu → `snidump` → navigates to `snidump_log.php`.

- [ ] **Step 6: Commit**

```bash
git add pkg/files/usr/local/www/snidump_log.php
git commit -m "feat(pkg): add snidump_log.php Bootstrap log/status viewer"
```

---

## Task 8: Update pkg-plist for PHP files and open PR 2

**Files:**
- Modify: `pkg/pkg-plist`

**Interfaces:**
- Produces: complete, installable `.pkg` with all files including XML and PHP

- [ ] **Step 1: Update pkg/pkg-plist to include all files**

Replace the existing `pkg/pkg-plist` with:

```
bin/snidump
bin/snidump_noether
etc/rc.d/snidump
@dir etc/newsyslog.conf.d
etc/newsyslog.conf.d/snidump
pkg/snidump.xml
pkg/snidump.inc
www/snidump_log.php
@dir(root,wheel,0750) /var/log/snidump
```

In `pkg/Makefile`, remove the `PLIST_FILES=` variable (it conflicts with `pkg-plist`; use one or the other — we use `pkg-plist`). In `do-install`, add:

```makefile
	${INSTALL_DATA} ${WRKSRC}/../snidump.xml \
		${STAGEDIR}${PREFIX}/pkg/snidump.xml
	${INSTALL_DATA} ${WRKSRC}/../files/usr/local/pkg/snidump.inc \
		${STAGEDIR}${PREFIX}/pkg/snidump.inc
	${INSTALL_DATA} ${WRKSRC}/../files/usr/local/www/snidump_log.php \
		${STAGEDIR}${PREFIX}/www/snidump_log.php
```

- [ ] **Step 2: Rebuild package and reinstall on pfSense**

```bash
make pkg-build
scp pkg/work/pkg/pfSense-pkg-snidump-0.1.0.pkg alvaro@pfsense:/tmp/
ssh alvaro@pfsense 'sudo pkg add /tmp/pfSense-pkg-snidump-0.1.0.pkg'
ssh alvaro@pfsense 'pkg info -l pfSense-pkg-snidump'
```

Expected: all files listed in plist are present on the system.

- [ ] **Step 3: End-to-end test on pfSense**

```bash
# 1. Navigate to pkg_edit.php?xml=snidump.xml&id=0
# 2. Select interface (e.g., em0), enable, JSON on, save
# 3. Verify /etc/rc.conf.local has correct snidump_* lines
ssh alvaro@pfsense 'grep snidump /etc/rc.conf.local'
# 4. Verify service is running
ssh alvaro@pfsense 'sudo service snidump status'
# 5. Verify newsyslog config was written
ssh alvaro@pfsense 'cat /etc/newsyslog.conf.d/snidump'
# 6. Navigate to snidump_log.php, verify status badge shows Running
# 7. Browse a few HTTPS sites from the LAN, verify JSON entries appear in log table
# 8. Check Status > Services — snidump should appear in the list
```

- [ ] **Step 4: Test deinstall**

```bash
ssh alvaro@pfsense 'sudo pkg remove pfSense-pkg-snidump'
ssh alvaro@pfsense 'grep snidump /etc/rc.conf.local; echo exit=$?'
ssh alvaro@pfsense 'ls /etc/newsyslog.conf.d/snidump; echo exit=$?'
```

Expected: `snidump_*` lines removed from rc.conf.local, newsyslog config deleted, service stopped.

- [ ] **Step 5: Commit and open PR 2**

```bash
git add pkg/pkg-plist pkg/Makefile
git commit -m "feat(pkg): update plist and Makefile for PHP web UI files; PR 2 complete"
# Open PR targeting master from feature/pfsense-package
```
