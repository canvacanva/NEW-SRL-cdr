<?php
/**
 * cdr.php - NEWCOMM
 * Export chiamate ESTERNE (effettuate / ricevute) dal DB cdr del PBX Wildix,
 * con riepilogo per ora (numero chiamate e minutaggio) oppure dettaglio.
 *
 * lo script è identico su ogni macchina. L'unica cosa per cliente è il
 * login web, in /var/credentials/cdr_export.php (fuori webroot):
 *   <?php
 *   $cdrweb_user = 'report';
 *   $cdrweb_hash = '...';
 * Generare l'hash con:
 *   php -r "echo password_hash('LA_PASSWORD', PASSWORD_DEFAULT), PHP_EOL;"
 *
 * Classificazione (campo dest_type del CDR Wildix):
 *   2 = chiamata in ingresso da esterno, 3 = chiamata in uscita verso esterno,
 *   4 = interna (esclusa), 0 = altro (escluso)
 */

declare(strict_types=1);

// NEWCOMM: DB identico su tutti i Wildix
const DB_HOST = 'localhost';
const DB_NAME = 'cdr';
const DB_USER = 'root';
const DB_PASS = 'PASSWORD_DB_WILDIX'; // cambiare psw

const CRED_FILE   = '/var/credentials/cdr_export.php';
const DEST_IN     = 2;
const DEST_OUT    = 3;
const MAX_DAYS    = 366;   // arco temporale massimo selezionabile
const SESSION_TTL = 1800;  // logout automatico dopo 30 minuti di inattività
const PREVIEW_MAX = 500;   // righe massime mostrate a video nel dettaglio

// Lettura login web: le variabili restano confinate nella closure
$cred = (function (string $f): array {
    if (!is_readable($f)) {
        return [];
    }
    require $f;
    return [
        'db_host'  => DB_HOST,
        'db_user'  => DB_USER,
        'db_pass'  => DB_PASS,
        'db_name'  => DB_NAME,
        'web_user' => $cdrweb_user ?? '',
        'web_hash' => $cdrweb_hash ?? '',
    ];
})(CRED_FILE);

if (!$cred || $cred['web_user'] === '' || $cred['web_hash'] === '') {
    http_response_code(500);
    exit('Configurazione mancante: verificare ' . CRED_FILE);
}

// ---------------------------------------------------------------- sessione
session_name('CDREXPORT');
session_set_cookie_params([
    'lifetime' => 0,
    'path'     => '/',
    'secure'   => !empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off',
    'httponly' => true,
    'samesite' => 'Strict',
]);
session_start();

header('X-Frame-Options: DENY');
header('X-Content-Type-Options: nosniff');
header('Cache-Control: no-store');

if (empty($_SESSION['csrf'])) {
    $_SESSION['csrf'] = bin2hex(random_bytes(16));
}

function h($s): string
{
    return htmlspecialchars((string)$s, ENT_QUOTES, 'UTF-8');
}

function csrfOk(): bool
{
    return isset($_POST['csrf']) && is_string($_POST['csrf'])
        && hash_equals($_SESSION['csrf'], $_POST['csrf']);
}

function redirectSelf(): void
{
    header('Location: ' . strtok($_SERVER['REQUEST_URI'], '?'));
    exit;
}

// Scadenza per inattività
if (!empty($_SESSION['auth']) && time() - ($_SESSION['last'] ?? 0) > SESSION_TTL) {
    $_SESSION = [];
    session_regenerate_id(true);
    $_SESSION['csrf'] = bin2hex(random_bytes(16));
}

$action = $_POST['action'] ?? '';
$error  = '';

// ---------------------------------------------------------------- login / logout
if ($action === 'login') {
    $u = (string)($_POST['user'] ?? '');
    $p = (string)($_POST['pass'] ?? '');
    if (csrfOk() && hash_equals($cred['web_user'], $u) && password_verify($p, $cred['web_hash'])) {
        session_regenerate_id(true);
        $_SESSION['auth']  = true;
        $_SESSION['last']  = time();
        $_SESSION['fails'] = 0;
        redirectSelf();
    }
    $_SESSION['fails'] = ($_SESSION['fails'] ?? 0) + 1;
    sleep(min(2 * $_SESSION['fails'], 10)); // rallenta i tentativi ripetuti
    $error = 'Utente o password non corretti.';
}

if ($action === 'logout' && csrfOk()) {
    $_SESSION = [];
    session_destroy();
    redirectSelf();
}

$logged = !empty($_SESSION['auth']);
if ($logged) {
    $_SESSION['last'] = time();
}

// ---------------------------------------------------------------- logica CDR
function secToHms(int $s): string
{
    return sprintf('%02d:%02d:%02d', intdiv($s, 3600), intdiv($s % 3600, 60), $s % 60);
}

function minutes(int $s): string
{
    return number_format($s / 60, 2, ',', '');
}

/**
 * NEWCOMM: tipo del numero esterno secondo la numerazione italiana:
 * 0... fisso, 3... mobile, +/00 non italiano estero, il resto (numeri verdi,
 * speciali, anonimi) altro.
 */
function numberType(string $n): string
{
    $n = preg_replace('/[^\d+]/', '', $n);
    if ($n === '') {
        return 'Altro';
    }
    if (strpos($n, '+39') === 0) {
        $n = substr($n, 3);
    } elseif (strpos($n, '0039') === 0) {
        $n = substr($n, 4);
    } elseif ($n[0] === '+' || strpos($n, '00') === 0) {
        return 'Estero';
    }
    if ($n === '') {
        return 'Altro';
    }
    if ($n[0] === '3') {
        return 'Mobile';
    }
    if ($n[0] === '0') {
        return 'Fisso';
    }
    return 'Altro';
}

/**
 * Chiamate esterne nell'intervallo [from, to).
 * NEWCOMM: una stessa chiamata può generare più righe CDR con lo stesso uniqueid
 * (es. passaggi trunk -> IVR -> coda); si tiene una sola riga per chiamata,
 * privilegiando quella risposta con conversazione più lunga.
 */
function externalCalls(mysqli $db, string $from, string $to): Generator
{
    $sql = "SELECT uniqueid, dest_type, start, src, dst, from_name, to_name,
                   disposition, duration, billsec
              FROM cdr
             WHERE start >= ? AND start < ?
               AND dest_type IN (" . DEST_IN . "," . DEST_OUT . ")
             ORDER BY start";
    $stmt = $db->prepare($sql);
    $stmt->bind_param('ss', $from, $to);
    $stmt->execute();
    $stmt->bind_result($uid, $destType, $start, $src, $dst, $fromName, $toName, $disp, $duration, $billsec);

    $calls = [];
    while ($stmt->fetch()) {
        $c = [
            'start'     => (string)$start,
            'dir'       => (int)$destType === DEST_IN ? 'IN' : 'OUT',
            'src'       => (string)$src,
            'from_name' => (string)$fromName,
            'dst'       => (string)$dst,
            'to_name'   => (string)$toName,
            'disp'      => (string)$disp,
            'duration'  => (int)$duration,
            'billsec'   => (int)$billsec,
        ];
        $c['kind'] = numberType($c['dir'] === 'IN' ? $c['src'] : $c['dst']);
        $key = $c['dir'] . '|' . ($uid !== null && $uid !== '' ? $uid : uniqid('', true));
        if (!isset($calls[$key])) {
            $calls[$key] = $c;
            continue;
        }
        // Riga duplicata: tengo la risposta più lunga, ma l'orario di inizio della prima
        $prev = $calls[$key];
        $better = ($c['disp'] === 'ANSWERED' && $prev['disp'] !== 'ANSWERED')
               || ($c['disp'] === $prev['disp'] && $c['billsec'] > $prev['billsec']);
        if ($better) {
            $c['start']    = $prev['start'];
            $c['duration'] = max($c['duration'], $prev['duration']);
            $calls[$key]   = $c;
        }
    }
    $stmt->close();

    foreach ($calls as $c) {
        yield $c;
    }
}

function emptyBucket(): array
{
    $b = [];
    foreach (['in', 'out'] as $p) {
        foreach (['tot', 'ans', 'sec', 'fix', 'fix_sec', 'mob', 'mob_sec'] as $k) {
            $b[$p . '_' . $k] = 0;
        }
    }
    return $b;
}

/** Riepilogo per giorno+ora o per sola fascia oraria */
function summary(Generator $calls, string $group): array
{
    $rows = [];
    if ($group === 'hour') {
        for ($i = 0; $i < 24; $i++) {
            $rows[sprintf('%02d:00-%02d:59', $i, $i)] = emptyBucket();
        }
    }
    foreach ($calls as $c) {
        $hour = substr($c['start'], 11, 2);
        $key  = $group === 'hour'
            ? $hour . ':00-' . $hour . ':59'
            : substr($c['start'], 0, 10) . ' ' . $hour . ':00';
        if (!isset($rows[$key])) {
            $rows[$key] = emptyBucket();
        }
        $p = $c['dir'] === 'IN' ? 'in' : 'out';
        $k = $c['kind'] === 'Fisso' ? 'fix' : ($c['kind'] === 'Mobile' ? 'mob' : null);
        $sec = $c['disp'] === 'ANSWERED' ? $c['billsec'] : 0;
        $rows[$key][$p . '_tot']++;
        if ($c['disp'] === 'ANSWERED') {
            $rows[$key][$p . '_ans']++;
            $rows[$key][$p . '_sec'] += $sec;
        }
        if ($k !== null) {
            $rows[$key][$p . '_' . $k]++;
            $rows[$key][$p . '_' . $k . '_sec'] += $sec;
        }
    }
    if ($group !== 'hour') {
        ksort($rows);
    }
    return $rows;
}

function summaryHeader(string $group): array
{
    return [
        $group === 'hour' ? 'Fascia oraria' : 'Data e ora',
        'Effettuate', 'Effettuate risposte', 'Minuti effettuate', 'Durata effettuate',
        'Eff. a fissi', 'Minuti eff. fissi', 'Eff. a mobili', 'Minuti eff. mobili',
        'Ricevute', 'Ricevute risposte', 'Minuti ricevute', 'Durata ricevute',
        'Ric. da fissi', 'Minuti ric. fissi', 'Ric. da mobili', 'Minuti ric. mobili',
        'Totale chiamate', 'Minuti totali',
    ];
}

function summaryLine(string $label, array $r): array
{
    $line = [$label];
    foreach (['out', 'in'] as $p) {
        array_push($line,
            $r[$p . '_tot'], $r[$p . '_ans'], minutes($r[$p . '_sec']), secToHms($r[$p . '_sec']),
            $r[$p . '_fix'], minutes($r[$p . '_fix_sec']), $r[$p . '_mob'], minutes($r[$p . '_mob_sec'])
        );
    }
    array_push($line, $r['out_tot'] + $r['in_tot'], minutes($r['out_sec'] + $r['in_sec']));
    return $line;
}

function totals(array $rows): array
{
    $t = emptyBucket();
    foreach ($rows as $r) {
        foreach ($t as $k => $v) {
            $t[$k] += $r[$k];
        }
    }
    return $t;
}

function detailHeader(): array
{
    return ['Data e ora', 'Direzione', 'Tipo numero', 'Da', 'Nome da', 'A', 'Nome a', 'Esito',
            'Durata totale (s)', 'Conversazione (s)', 'Minuti conversazione'];
}

function detailLine(array $c): array
{
    return [
        $c['start'], $c['dir'] === 'IN' ? 'Ricevuta' : 'Effettuata', $c['kind'],
        $c['src'], $c['from_name'], $c['dst'], $c['to_name'], $c['disp'],
        $c['duration'], $c['billsec'], minutes($c['billsec']),
    ];
}

/** Riga di totale per il dettaglio: conteggi e minuti per direzione e tipo numero */
function detailTotals(array $calls): array
{
    $t = ['IN' => [0, 0, 0, 0, 0], 'OUT' => [0, 0, 0, 0, 0]]; // tot, fissi, mobili, sec, risposte
    foreach ($calls as $c) {
        $d = $c['dir'];
        $t[$d][0]++;
        if ($c['kind'] === 'Fisso') {
            $t[$d][1]++;
        } elseif ($c['kind'] === 'Mobile') {
            $t[$d][2]++;
        }
        if ($c['disp'] === 'ANSWERED') {
            $t[$d][3] += $c['billsec'];
            $t[$d][4]++;
        }
    }
    return $t;
}

function detailTotalsLine(array $calls): array
{
    $t = detailTotals($calls);
    return [
        'TOTALE',
        'Effettuate: ' . $t['OUT'][0] . ' (fissi ' . $t['OUT'][1] . ', mobili ' . $t['OUT'][2] . ', risposte ' . $t['OUT'][4] . ')',
        'Minuti effettuate: ' . minutes($t['OUT'][3]),
        'Ricevute: ' . $t['IN'][0] . ' (fissi ' . $t['IN'][1] . ', mobili ' . $t['IN'][2] . ', risposte ' . $t['IN'][4] . ')',
        'Minuti ricevute: ' . minutes($t['IN'][3]),
        'Minuti totali: ' . minutes($t['OUT'][3] + $t['IN'][3]),
    ];
}

// ---------------------------------------------------------------- parametri form
$today   = date('Y-m-d');
$fFrom   = (string)($_POST['from'] ?? date('Y-m-01'));
$fTo     = (string)($_POST['to'] ?? $today);
$fGroup  = ($_POST['group'] ?? 'day_hour') === 'hour' ? 'hour' : 'day_hour';
$fType   = ($_POST['type'] ?? 'summary') === 'detail' ? 'detail' : 'summary';
$preview = null;

if ($logged && $action === 'export') {
    $dFrom = DateTime::createFromFormat('!Y-m-d', $fFrom);
    $dTo   = DateTime::createFromFormat('!Y-m-d', $fTo);

    if (!csrfOk()) {
        $error = 'Sessione scaduta, ricaricare la pagina.';
    } elseif (!$dFrom || !$dTo || $dFrom->format('Y-m-d') !== $fFrom || $dTo->format('Y-m-d') !== $fTo) {
        $error = 'Date non valide.';
    } elseif ($dTo < $dFrom) {
        $error = 'La data finale è precedente a quella iniziale.';
    } elseif ($dFrom->diff($dTo)->days >= MAX_DAYS) {
        $error = 'L\'intervallo massimo è di ' . MAX_DAYS . ' giorni.';
    } else {
        $sqlFrom = $dFrom->format('Y-m-d 00:00:00');
        $sqlTo   = (clone $dTo)->modify('+1 day')->format('Y-m-d 00:00:00');

        try {
            mysqli_report(MYSQLI_REPORT_ERROR | MYSQLI_REPORT_STRICT);
            $db = new mysqli($cred['db_host'], $cred['db_user'], $cred['db_pass'], $cred['db_name']);
            $db->set_charset('utf8mb4');
        } catch (mysqli_sql_exception $e) {
            error_log('cdr_export: connessione DB fallita: ' . $e->getMessage());
            $db    = null;
            $error = 'Connessione al database non riuscita.';
        }

        if ($db && ($_POST['out'] ?? '') === 'csv') {
            $name = sprintf('chiamate_esterne_%s_%s_%s.csv', $fFrom, $fTo,
                $fType === 'detail' ? 'dettaglio' : ($fGroup === 'hour' ? 'fasce_orarie' : 'per_ora'));
            header('Content-Type: text/csv; charset=UTF-8');
            header('Content-Disposition: attachment; filename="' . $name . '"');
            $fh = fopen('php://output', 'w');
            fwrite($fh, "\xEF\xBB\xBF"); // BOM per apertura corretta in Excel

            if ($fType === 'detail') {
                $calls = iterator_to_array(externalCalls($db, $sqlFrom, $sqlTo), false);
                // NEWCOMM: totale in alto
                fputcsv($fh, detailTotalsLine($calls), ';');
                fputcsv($fh, [], ';');
                fputcsv($fh, detailHeader(), ';');
                foreach ($calls as $c) {
                    fputcsv($fh, detailLine($c), ';');
                }
            } else {
                $rows = summary(externalCalls($db, $sqlFrom, $sqlTo), $fGroup);
                fputcsv($fh, summaryHeader($fGroup), ';');
                fputcsv($fh, summaryLine('TOTALE', totals($rows)), ';'); // NEWCOMM: totale in alto
                foreach ($rows as $label => $r) {
                    fputcsv($fh, summaryLine($label, $r), ';');
                }
            }
            fclose($fh);
            $db->close();
            exit;
        }

        if ($db) {
            if ($fType === 'detail') {
                $calls = iterator_to_array(externalCalls($db, $sqlFrom, $sqlTo), false);
                $list  = array_map('detailLine', array_slice($calls, 0, PREVIEW_MAX));
                $preview = ['head' => detailHeader(), 'rows' => $list, 'count' => count($calls),
                            'dtot' => detailTotals($calls)];
            } else {
                $rows  = summary(externalCalls($db, $sqlFrom, $sqlTo), $fGroup);
                $lines = [];
                foreach ($rows as $label => $r) {
                    $lines[] = summaryLine($label, $r);
                }
                $preview = ['head' => summaryHeader($fGroup), 'rows' => $lines,
                            'total' => summaryLine('Totale', totals($rows))];
            }
            $db->close();
        }
    }
}
?>
<!DOCTYPE html>
<html lang="it">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>Registro chiamate esterne</title>
<style>
:root {
    color-scheme: light;
    --bg: #eef1f4; --panel: #ffffff; --ink: #1d2733; --muted: #5d6b7a;
    --line: #d5dbe2; --accent: #1f5f8b; --accent-ink: #ffffff; --err: #a3262a;
    --in: #2f7d5b; --out: #1f5f8b;
}
@media (prefers-color-scheme: dark) {
    :root {
        color-scheme: dark;
        --bg: #151b22; --panel: #1e2630; --ink: #e3e8ee; --muted: #9aa7b5;
        --line: #33404e; --accent: #5ea4d6; --accent-ink: #0f1720; --err: #ef8a8d;
        --in: #6cc49c; --out: #5ea4d6;
    }
}
* { box-sizing: border-box; }
body { margin: 0; background: var(--bg); color: var(--ink);
       font: 15px/1.5 system-ui, -apple-system, "Segoe UI", Roboto, sans-serif; }
main { max-width: 1100px; margin: 0 auto; padding: 32px 20px 48px; }
header { display: flex; justify-content: space-between; align-items: baseline; gap: 16px; margin-bottom: 20px; }
h1 { font-size: 22px; font-weight: 600; margin: 0; }
.sub { color: var(--muted); margin: 2px 0 0; font-size: 14px; }
.panel { background: var(--panel); border: 1px solid var(--line); border-radius: 6px; padding: 20px; }
.login { max-width: 360px; margin: 12vh auto 0; }
form.grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(170px, 1fr)); gap: 14px 18px; align-items: end; }
label { display: block; font-size: 13px; color: var(--muted); margin-bottom: 4px; }
input, select { width: 100%; padding: 8px 10px; font: inherit; color: var(--ink);
                background: var(--bg); border: 1px solid var(--line); border-radius: 4px; }
input:focus, select:focus, button:focus-visible { outline: 2px solid var(--accent); outline-offset: 1px; }
.login input { margin-bottom: 14px; }
.presets { grid-column: 1 / -1; display: flex; flex-wrap: wrap; gap: 8px; }
.presets button { background: transparent; color: var(--accent); border: 1px solid var(--line);
                  padding: 4px 10px; font-size: 13px; }
.actions { grid-column: 1 / -1; display: flex; gap: 10px; flex-wrap: wrap; }
button { font: inherit; padding: 8px 16px; border-radius: 4px; border: 1px solid var(--accent);
         background: var(--accent); color: var(--accent-ink); cursor: pointer; }
button.ghost { background: transparent; color: var(--accent); }
.link { background: none; border: none; color: var(--muted); padding: 0; text-decoration: underline; }
.err { color: var(--err); margin: 0 0 14px; }
.note { color: var(--muted); font-size: 13px; margin: 12px 0 0; }
.tablewrap { overflow-x: auto; margin-top: 20px; }
table { border-collapse: collapse; width: 100%; font-size: 14px; font-variant-numeric: tabular-nums; }
th, td { padding: 6px 10px; border-bottom: 1px solid var(--line); text-align: right; white-space: nowrap; }
th:first-child, td:first-child { text-align: left; }
th { font-weight: 600; color: var(--muted); position: sticky; top: 0; background: var(--panel); }
td.in { color: var(--in); } td.out { color: var(--out); }
tr.total td { font-weight: 600; border-bottom: 2px solid var(--line); background: var(--bg); }
table.totals { width: auto; margin-bottom: 8px; }
</style>
</head>
<body>
<main>
<?php if (!$logged): ?>
    <div class="panel login">
        <h1>Registro chiamate esterne</h1>
        <p class="sub">Accedi per scaricare il registro.</p>
        <?php if ($error): ?><p class="err"><?= h($error) ?></p><?php endif; ?>
        <form method="post" autocomplete="off" style="margin-top:16px">
            <input type="hidden" name="action" value="login">
            <input type="hidden" name="csrf" value="<?= h($_SESSION['csrf']) ?>">
            <label for="user">Utente</label>
            <input id="user" name="user" required autofocus>
            <label for="pass">Password</label>
            <input id="pass" name="pass" type="password" required>
            <button type="submit">Accedi</button>
        </form>
    </div>
<?php else: ?>
    <header>
        <div>
            <h1>Registro chiamate esterne</h1>
            <p class="sub">Chiamate effettuate e ricevute verso numeri esterni, con minutaggio di conversazione.</p>
        </div>
        <form method="post">
            <input type="hidden" name="action" value="logout">
            <input type="hidden" name="csrf" value="<?= h($_SESSION['csrf']) ?>">
            <button class="link" type="submit">Esci</button>
        </form>
    </header>

    <div class="panel">
        <?php if ($error): ?><p class="err"><?= h($error) ?></p><?php endif; ?>
        <form method="post" class="grid" id="f">
            <input type="hidden" name="action" value="export">
            <input type="hidden" name="csrf" value="<?= h($_SESSION['csrf']) ?>">
            <div class="presets">
                <button type="button" data-p="today">Oggi</button>
                <button type="button" data-p="yesterday">Ieri</button>
                <button type="button" data-p="week">Ultimi 7 giorni</button>
                <button type="button" data-p="month">Mese corrente</button>
                <button type="button" data-p="lastmonth">Mese scorso</button>
            </div>
            <div><label for="from">Dal</label>
                <input type="date" id="from" name="from" value="<?= h($fFrom) ?>" max="<?= h($today) ?>" required></div>
            <div><label for="to">Al</label>
                <input type="date" id="to" name="to" value="<?= h($fTo) ?>" max="<?= h($today) ?>" required></div>
            <div><label for="type">Contenuto</label>
                <select id="type" name="type">
                    <option value="summary" <?= $fType === 'summary' ? 'selected' : '' ?>>Riepilogo per ora</option>
                    <option value="detail" <?= $fType === 'detail' ? 'selected' : '' ?>>Dettaglio chiamate</option>
                </select></div>
            <div><label for="group">Raggruppamento riepilogo</label>
                <select id="group" name="group">
                    <option value="day_hour" <?= $fGroup === 'day_hour' ? 'selected' : '' ?>>Giorno e ora</option>
                    <option value="hour" <?= $fGroup === 'hour' ? 'selected' : '' ?>>Fascia oraria (tutti i giorni)</option>
                </select></div>
            <div class="actions">
                <button type="submit" name="out" value="csv">Scarica CSV</button>
                <button type="submit" name="out" value="screen" class="ghost">Mostra a video</button>
            </div>
        </form>
        <p class="note">I minuti si riferiscono alla sola conversazione (chiamate risposte). Le chiamate tra interni sono escluse.</p>

        <?php if ($preview): ?>
            <div class="tablewrap">
            <?php if ($fType === 'detail'): $t = $preview['dtot']; ?>
                <table class="totals">
                    <thead><tr><th></th><th>Chiamate</th><th>Risposte</th><th>Da/a fissi</th><th>Da/a mobili</th><th>Minuti</th></tr></thead>
                    <tbody>
                        <tr><td class="out">Effettuate</td><td><?= $t['OUT'][0] ?></td><td><?= $t['OUT'][4] ?></td><td><?= $t['OUT'][1] ?></td><td><?= $t['OUT'][2] ?></td><td><?= minutes($t['OUT'][3]) ?></td></tr>
                        <tr><td class="in">Ricevute</td><td><?= $t['IN'][0] ?></td><td><?= $t['IN'][4] ?></td><td><?= $t['IN'][1] ?></td><td><?= $t['IN'][2] ?></td><td><?= minutes($t['IN'][3]) ?></td></tr>
                        <tr class="total"><td>Totale</td><td><?= $t['OUT'][0] + $t['IN'][0] ?></td><td><?= $t['OUT'][4] + $t['IN'][4] ?></td><td><?= $t['OUT'][1] + $t['IN'][1] ?></td><td><?= $t['OUT'][2] + $t['IN'][2] ?></td><td><?= minutes($t['OUT'][3] + $t['IN'][3]) ?></td></tr>
                    </tbody>
                </table>
                <p class="note"><?= $preview['count'] ?> chiamate esterne nel periodo<?= $preview['count'] > PREVIEW_MAX ? ', mostrate le prime ' . PREVIEW_MAX . ': scarica il CSV per l\'elenco completo' : '' ?>.</p>
            <?php endif; ?>
            <?php if (!$preview['rows'] || ($fType === 'detail' && !$preview['count'])): ?>
                <p class="note">Nessuna chiamata esterna nel periodo selezionato.</p>
            <?php else: ?>
                <table>
                    <thead><tr><?php foreach ($preview['head'] as $c): ?><th><?= h($c) ?></th><?php endforeach; ?></tr></thead>
                    <tbody>
                    <?php if (isset($preview['total'])): // NEWCOMM: totale in alto ?>
                        <tr class="total"><?php foreach ($preview['total'] as $v): ?><td><?= h($v) ?></td><?php endforeach; ?></tr>
                    <?php endif; ?>
                    <?php foreach ($preview['rows'] as $r): ?>
                        <tr><?php foreach ($r as $i => $v):
                            $cls = '';
                            if ($fType === 'detail' && $i === 1) { $cls = $v === 'Ricevuta' ? 'in' : 'out'; }
                        ?><td class="<?= $cls ?>"><?= h($v) ?></td><?php endforeach; ?></tr>
                    <?php endforeach; ?>
                    </tbody>
                </table>
            <?php endif; ?>
            </div>
        <?php endif; ?>
    </div>
<script>
(function () {
    var f = document.getElementById('from'), t = document.getElementById('to');
    function iso(d) { return d.getFullYear() + '-' + String(d.getMonth() + 1).padStart(2, '0') + '-' + String(d.getDate()).padStart(2, '0'); }
    document.querySelectorAll('.presets button').forEach(function (b) {
        b.addEventListener('click', function () {
            var n = new Date(), a = new Date(n), z = new Date(n);
            switch (b.dataset.p) {
                case 'yesterday': a.setDate(n.getDate() - 1); z = new Date(a); break;
                case 'week':      a.setDate(n.getDate() - 6); break;
                case 'month':     a = new Date(n.getFullYear(), n.getMonth(), 1); break;
                case 'lastmonth': a = new Date(n.getFullYear(), n.getMonth() - 1, 1);
                                  z = new Date(n.getFullYear(), n.getMonth(), 0); break;
            }
            f.value = iso(a); t.value = iso(z);
        });
    });
})();
</script>
<?php endif; ?>
</main>
</body>
</html>
