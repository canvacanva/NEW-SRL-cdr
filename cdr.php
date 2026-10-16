<?php
/**
 * cdr.php - NEWCOMM
 * Registro chiamate ESTERNE dal DB cdr del PBX Wildix, per la fatturazione:
 *  - riepilogo giorno per giorno (chiamate e minuti, effettuate / ricevute, fissi / mobili)
 *  - dettaglio di un giorno con l'elenco completo delle chiamate e i numeri
 *  - export CSV del riepilogo, del dettaglio del periodo o del singolo giorno
 *
 * Si considerano SOLO:
 *  - chiamate effettuate verso numeri esterni al centralino (dest_type 3, uscite da trunk)
 *  - chiamate ricevute da numeri esterni pubblici (dest_type 2); le anonime sono escluse
 *  - le chiamate mobility (interno inoltrato al cellulare via trunk) sono effettuate a tutti gli effetti
 *    salvo INCLUDE_ANONYMOUS = true
 * Le chiamate tra interni (dest_type 4) e le altre (dest_type 0) sono escluse.
 *
 * Il DB cdr ha la stessa struttura e le stesse credenziali su tutti i PBX Wildix,
 * quindi lo script è identico su ogni macchina. L'unica cosa per cliente è il
 * login web, in /var/credentials/cdr_export.php (fuori webroot):
 *   <?php
 *   $cdrweb_user = 'report';
 *   $cdrweb_hash = '...';
 * Generare l'hash con:
 *   php -r "echo password_hash('LA_PASSWORD', PASSWORD_DEFAULT), PHP_EOL;"
 */

declare(strict_types=1);

const DB_HOST = 'localhost';
const DB_NAME = 'cdr';
const DB_USER = 'root';
const DB_PASS = 'PASSWORD_DB_WILDIX'; // cambiare psw

const CRED_FILE         = '/var/credentials/cdr_export.php';
const DEST_IN           = 2;
const DEST_OUT          = 3;
const INCLUDE_ANONYMOUS = false; // true per conteggiare anche le ricevute da numero nascosto
const MAX_DAYS          = 366;   // arco temporale massimo selezionabile
const MERGE_GAP         = 60;    // secondi entro cui righe sullo stesso canale trunk sono la stessa chiamata
const SESSION_TTL       = 1800;  // logout automatico dopo 30 minuti di inattività

// Lettura login web: le variabili restano confinate nella closure
$cred = (function (string $f): array {
    if (!is_readable($f)) {
        return [];
    }
    require $f;
    return [
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

function selfUrl(array $params = []): string
{
    $base = strtok($_SERVER['REQUEST_URI'], '?');
    return $params ? $base . '?' . http_build_query($params) : $base;
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
        header('Location: ' . selfUrl());
        exit;
    }
    $_SESSION['fails'] = ($_SESSION['fails'] ?? 0) + 1;
    sleep(min(2 * $_SESSION['fails'], 10)); // rallenta i tentativi ripetuti
    $error = 'Utente o password non corretti.';
}

if ($action === 'logout' && csrfOk()) {
    $_SESSION = [];
    session_destroy();
    header('Location: ' . selfUrl());
    exit;
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

function parseDate(string $s): ?DateTime
{
    $d = DateTime::createFromFormat('!Y-m-d', $s);
    return ($d && $d->format('Y-m-d') === $s) ? $d : null;
}

function dayLabel(string $ymd): string
{
    $d = DateTime::createFromFormat('!Y-m-d', $ymd);
    $g = ['dom', 'lun', 'mar', 'mer', 'gio', 'ven', 'sab'][(int)$d->format('w')];
    return $g . ' ' . $d->format('d/m/Y');
}

function esito(string $disp): string
{
    $map = ['ANSWERED' => 'Risposta', 'NO ANSWER' => 'Non risposta', 'BUSY' => 'Occupato', 'FAILED' => 'Non riuscita'];
    return $map[$disp] ?? $disp;
}

/**
 * Tipo del numero esterno (formato E.164 dei campi c_from / c_to):
 * +39 0... fisso, +39 3... mobile, +39 80... numero verde, altri +39 speciale,
 * prefisso internazionale diverso da +39 estero.
 */
function numberType(string $n): string
{
    $n = preg_replace('/[^\d+]/', '', $n);
    if (strpos($n, '+39') === 0) {
        $n = substr($n, 3);
    } elseif (strpos($n, '0039') === 0) {
        $n = substr($n, 4);
    } elseif ($n !== '' && ($n[0] === '+' || strpos($n, '00') === 0)) {
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
    if (strpos($n, '80') === 0) {
        return 'Numero verde';
    }
    return 'Speciale';
}

/** Numero esterno "pubblico": solo cifre, almeno 3 (esclude anonimi e numeri nascosti) */
function isPublicNumber(string $n): bool
{
    return preg_match('/^\+?\d{3,}$/', preg_replace('/[\s\-().]/', '', $n)) === 1;
}

/** Nome del trunk dal canale, es. SIP/50445446749-00000b30 -> 50445446749 */
function trunkName(string $chan): string
{
    return preg_match('#^[A-Za-z]+/([^-@;]+)-#', $chan, $m) ? $m[1] : '';
}

/**
 * Chiamate esterne nell'intervallo [from, to), ordinate per inizio.
 *
 * NEWCOMM: il numero esterno si legge da c_from (ricevute) e c_to (effettuate),
 * già normalizzati in +39...; src/dst contengono il prefisso di uscita (0) e,
 * nelle chiamate mobility, il numero dell'interno.
 *
 * NEWCOMM: una chiamata sul trunk può generare più righe CDR (coda, trasferimenti
 * con uniqueid diverso). Le righe vengono unite usando il canale del trunk
 * (channel per le ricevute, dstchannel per le effettuate) quando si susseguono
 * entro MERGE_GAP secondi; la conversazione va dalla prima risposta all'ultima
 * chiusura, gli interni coinvolti vengono elencati in ordine.
 */
function externalCalls(mysqli $db, string $from, string $to): array
{
    $sql = "SELECT uniqueid, dest_type, start, answer, `end`, c_from, c_to, from_name, to_name,
                   disposition, billsec, channel, dstchannel, lastapp, dcontext
              FROM cdr
             WHERE start >= ? AND start < ?
               AND dest_type IN (" . DEST_IN . "," . DEST_OUT . ")
             ORDER BY start, rowid";
    $stmt = $db->prepare($sql);
    $stmt->bind_param('ss', $from, $to);
    $stmt->execute();
    $stmt->bind_result($uid, $destType, $start, $answer, $end, $cFrom, $cTo, $fromName, $toName,
                       $disp, $billsec, $channel, $dstChannel, $lastApp, $dcontext);

    $calls = [];
    $open  = [];
    while ($stmt->fetch()) {
        $in       = (int)$destType === DEST_IN;
        $tStart   = (int)strtotime((string)$start);
        $tEnd     = max($tStart, (int)strtotime((string)$end));
        $answered = (string)$disp === 'ANSWERED';
        $tAns     = $answered ? max($tStart, (int)strtotime((string)$answer)) : 0;
        $trunkCh  = (string)($in ? $channel : $dstChannel);
        $key      = ($in ? 'IN' : 'OUT') . '|' . ($trunkCh !== '' ? $trunkCh : 'uid:' . $uid);

        $ext     = trim((string)($in ? $cFrom : $cTo));
        $extName = trim((string)($in ? $fromName : $toName));
        $intNum  = trim((string)($in ? $cTo : $cFrom));
        $intName = trim((string)($in ? $toName : $fromName));

        $notes = [];
        if ((string)$lastApp === 'ReceiveFAX') {
            $notes[] = 'Fax';
        }
        if (strpos((string)$channel, '@mobility') !== false || (string)$dcontext === 'mobility') {
            $notes[] = 'Mobility';
        }

        if (isset($open[$key]) && $tStart <= $calls[$open[$key]]['t_end'] + MERGE_GAP) {
            // Altra riga della stessa chiamata sul trunk
            $c = &$calls[$open[$key]];
            $c['t_end'] = max($c['t_end'], $tEnd);
            $c['legs']++;
            if ($answered) {
                $c['t_ans']     = $c['t_ans'] ? min($c['t_ans'], $tAns) : $tAns;
                $c['t_ans_end'] = max($c['t_ans_end'], $tEnd);
                $c['disp']      = 'ANSWERED';
                $c['billsec']   = (int)$billsec;
            }
            if (!isPublicNumber($c['ext']) && isPublicNumber($ext)) {
                $c['ext'] = $ext;
                $c['ext_name'] = $extName;
            }
            if ($intNum !== '' && !in_array($intNum, $c['ints'], true)) {
                $c['ints'][]     = $intNum;
                $c['int_names'][] = $intName;
            }
            $c['notes'] = array_values(array_unique(array_merge($c['notes'], $notes)));
            unset($c);
            continue;
        }

        $calls[] = [
            't_start'   => $tStart,
            't_end'     => $tEnd,
            't_ans'     => $tAns,
            't_ans_end' => $answered ? $tEnd : 0,
            'legs'      => 1,
            'dir'       => $in ? 'IN' : 'OUT',
            'ext'       => $ext,
            'ext_name'  => $extName,
            'ints'      => $intNum !== '' ? [$intNum] : [],
            'int_names' => $intNum !== '' ? [$intName] : [],
            'trunk'     => trunkName($trunkCh),
            'notes'     => $notes,
            'disp'      => (string)$disp,
            'billsec'   => (int)$billsec,
        ];
        $open[$key] = count($calls) - 1;
    }
    $stmt->close();

    $out = [];
    foreach ($calls as $c) {
        if ($c['dir'] === 'IN' && !INCLUDE_ANONYMOUS && !isPublicNumber($c['ext'])) {
            continue; // ricevuta senza numero pubblico
        }
        if ($c['dir'] === 'OUT' && $c['ext'] === '') {
            continue;
        }
        if ($c['disp'] !== 'ANSWERED') {
            $c['billsec'] = 0;
        } elseif ($c['legs'] > 1) {
            // Più tratte: conversazione dalla prima risposta all'ultima chiusura
            $c['billsec'] = max(0, $c['t_ans_end'] - $c['t_ans']);
        }
        $c['start']    = date('Y-m-d H:i:s', $c['t_start']);
        $c['duration'] = $c['t_end'] - $c['t_start'];
        $c['kind']     = numberType($c['ext']);
        $c['int']      = implode(' > ', $c['ints']);
        $c['int_name'] = implode(' > ', array_filter($c['int_names'], 'strlen'));
        $c['note']     = implode(', ', $c['notes']);
        $out[] = $c;
    }
    return $out;
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

function addCall(array &$b, array $c): void
{
    $p   = $c['dir'] === 'IN' ? 'in' : 'out';
    $sec = $c['disp'] === 'ANSWERED' ? $c['billsec'] : 0;
    $b[$p . '_tot']++;
    if ($c['disp'] === 'ANSWERED') {
        $b[$p . '_ans']++;
        $b[$p . '_sec'] += $sec;
    }
    $k = $c['kind'] === 'Fisso' ? 'fix' : ($c['kind'] === 'Mobile' ? 'mob' : null);
    if ($k !== null) {
        $b[$p . '_' . $k]++;
        $b[$p . '_' . $k . '_sec'] += $sec;
    }
}

/** Riepilogo giorno per giorno, compresi i giorni senza chiamate */
function byDay(array $calls, DateTime $from, DateTime $to): array
{
    $rows = [];
    for ($d = clone $from; $d <= $to; $d->modify('+1 day')) {
        $rows[$d->format('Y-m-d')] = emptyBucket();
    }
    foreach ($calls as $c) {
        $key = substr($c['start'], 0, 10);
        if (isset($rows[$key])) {
            addCall($rows[$key], $c);
        }
    }
    return $rows;
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

function totalsFromCalls(array $calls): array
{
    $t = emptyBucket();
    foreach ($calls as $c) {
        addCall($t, $c);
    }
    return $t;
}

function summaryHeader(): array
{
    return [
        'Giorno',
        'Effettuate', 'Effettuate risposte', 'Minuti effettuate',
        'Eff. a fissi', 'Minuti eff. fissi', 'Eff. a mobili', 'Minuti eff. mobili',
        'Ricevute', 'Ricevute risposte', 'Minuti ricevute',
        'Ric. da fissi', 'Minuti ric. fissi', 'Ric. da mobili', 'Minuti ric. mobili',
        'Totale chiamate', 'Minuti totali',
    ];
}

function summaryValues(array $r): array
{
    $v = [];
    foreach (['out', 'in'] as $p) {
        array_push($v,
            $r[$p . '_tot'], $r[$p . '_ans'], minutes($r[$p . '_sec']),
            $r[$p . '_fix'], minutes($r[$p . '_fix_sec']), $r[$p . '_mob'], minutes($r[$p . '_mob_sec'])
        );
    }
    array_push($v, $r['out_tot'] + $r['in_tot'], minutes($r['out_sec'] + $r['in_sec']));
    return $v;
}

/** Blocco totali compatto: effettuate, ricevute, totale */
function totalsBlock(array $t): array
{
    $line = function (string $label, array $p) use ($t): array {
        $s = function (string $k) use ($t, $p): int {
            return array_sum(array_map(function ($x) use ($t, $k) { return $t[$x . '_' . $k]; }, $p));
        };
        return [$label, $s('tot'), $s('ans'), $s('fix'), $s('mob'), minutes($s('sec')), secToHms($s('sec'))];
    };
    return [
        ['', 'Chiamate', 'Risposte', 'Fissi', 'Mobili', 'Minuti', 'Durata'],
        $line('Effettuate', ['out']),
        $line('Ricevute', ['in']),
        $line('Totale', ['out', 'in']),
    ];
}

function detailHeader(): array
{
    return ['Data', 'Ora', 'Direzione', 'Tipo numero', 'Numero esterno', 'Nome esterno',
            'Interno', 'Nome interno', 'Linea', 'Note', 'Esito', 'Durata totale (s)',
            'Conversazione (s)', 'Durata conversazione', 'Minuti conversazione'];
}

function detailLine(array $c): array
{
    return [
        substr($c['start'], 8, 2) . '/' . substr($c['start'], 5, 2) . '/' . substr($c['start'], 0, 4),
        substr($c['start'], 11, 8),
        $c['dir'] === 'IN' ? 'Ricevuta' : 'Effettuata',
        $c['kind'], $c['ext'], $c['ext_name'], $c['int'], $c['int_name'],
        $c['trunk'], $c['note'], esito($c['disp']), $c['duration'], $c['billsec'], secToHms($c['billsec']), minutes($c['billsec']),
    ];
}

function csvStart(string $name)
{
    header('Content-Type: text/csv; charset=UTF-8');
    header('Content-Disposition: attachment; filename="' . $name . '"');
    $fh = fopen('php://output', 'w');
    fwrite($fh, "\xEF\xBB\xBF"); // BOM per apertura corretta in Excel
    return $fh;
}

// ---------------------------------------------------------------- richiesta
$today = date('Y-m-d');
$fFrom = (string)($_GET['from'] ?? date('Y-m-01'));
$fTo   = (string)($_GET['to'] ?? $today);
$view  = (string)($_GET['view'] ?? '');
$csv   = (string)($_GET['csv'] ?? '');
$fDay  = (string)($_GET['day'] ?? '');

$rows = $calls = $tot = null;

if ($logged && ($view !== '' || $csv !== '')) {
    $dFrom = parseDate($fFrom);
    $dTo   = parseDate($fTo);
    $dDay  = $view === 'day' ? parseDate($fDay) : null;

    if ($view === 'day' && !$dDay) {
        $error = 'Giorno non valido.';
    } elseif ($view !== 'day' && (!$dFrom || !$dTo)) {
        $error = 'Date non valide.';
    } elseif ($view !== 'day' && $dTo < $dFrom) {
        $error = 'La data finale è precedente a quella iniziale.';
    } elseif ($view !== 'day' && $dFrom->diff($dTo)->days >= MAX_DAYS) {
        $error = 'L\'intervallo massimo è di ' . MAX_DAYS . ' giorni.';
    } else {
        // Nel dettaglio giornaliero il periodo interrogato è il solo giorno scelto
        $qFrom = $view === 'day' ? $dDay : $dFrom;
        $qTo   = $view === 'day' ? $dDay : $dTo;

        try {
            mysqli_report(MYSQLI_REPORT_ERROR | MYSQLI_REPORT_STRICT);
            $db = new mysqli(DB_HOST, DB_USER, DB_PASS, DB_NAME);
            $db->set_charset('utf8mb4');
            $calls = externalCalls(
                $db,
                $qFrom->format('Y-m-d 00:00:00'),
                (clone $qTo)->modify('+1 day')->format('Y-m-d 00:00:00')
            );
            $db->close();
        } catch (mysqli_sql_exception $e) {
            error_log('cdr.php: errore DB: ' . $e->getMessage());
            $calls = null;
            $error = 'Lettura dal database non riuscita.';
        }

        if ($calls !== null && $csv === 'summary') {
            $rows = byDay($calls, $qFrom, $qTo);
            $fh = csvStart(sprintf('chiamate_esterne_riepilogo_%s_%s.csv', $fFrom, $fTo));
            fputcsv($fh, summaryHeader(), ';');
            fputcsv($fh, array_merge(['TOTALE'], summaryValues(totals($rows))), ';'); // totale in alto
            foreach ($rows as $day => $r) {
                fputcsv($fh, array_merge([dayLabel($day)], summaryValues($r)), ';');
            }
            fclose($fh);
            exit;
        }

        if ($calls !== null && $csv === 'detail') {
            $name = $view === 'day'
                ? sprintf('chiamate_esterne_%s.csv', $fDay)
                : sprintf('chiamate_esterne_dettaglio_%s_%s.csv', $fFrom, $fTo);
            $fh = csvStart($name);
            foreach (totalsBlock(totalsFromCalls($calls)) as $line) { // totale in alto
                fputcsv($fh, $line, ';');
            }
            fputcsv($fh, [], ';');
            fputcsv($fh, detailHeader(), ';');
            foreach ($calls as $c) {
                fputcsv($fh, detailLine($c), ';');
            }
            fclose($fh);
            exit;
        }

        if ($calls !== null) {
            if ($view === 'day') {
                $tot = totalsFromCalls($calls);
            } else {
                $view = 'summary';
                $rows = byDay($calls, $qFrom, $qTo);
                $tot  = totals($rows);
            }
        }
    }
}

// Parametri per i link di ritorno e di navigazione
$range = ['from' => $fFrom, 'to' => $fTo];
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
    --in: #2f7d5b; --out: #1f5f8b; --zero: #a9b3bd;
}
@media (prefers-color-scheme: dark) {
    :root {
        color-scheme: dark;
        --bg: #151b22; --panel: #1e2630; --ink: #e3e8ee; --muted: #9aa7b5;
        --line: #33404e; --accent: #5ea4d6; --accent-ink: #0f1720; --err: #ef8a8d;
        --in: #6cc49c; --out: #5ea4d6; --zero: #55626f;
    }
}
* { box-sizing: border-box; }
body { margin: 0; background: var(--bg); color: var(--ink);
       font: 15px/1.5 system-ui, -apple-system, "Segoe UI", Roboto, sans-serif; }
main { max-width: 1280px; margin: 0 auto; padding: 32px 20px 48px; }
header { display: flex; justify-content: space-between; align-items: baseline; gap: 16px; margin-bottom: 20px; }
h1 { font-size: 22px; font-weight: 600; margin: 0; }
h2 { font-size: 18px; font-weight: 600; margin: 0; }
.sub { color: var(--muted); margin: 2px 0 0; font-size: 14px; }
.panel { background: var(--panel); border: 1px solid var(--line); border-radius: 6px; padding: 20px; }
.panel + .panel { margin-top: 16px; }
.login { max-width: 360px; margin: 12vh auto 0; }
form.grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(170px, 1fr)); gap: 14px 18px; align-items: end; }
label { display: block; font-size: 13px; color: var(--muted); margin-bottom: 4px; }
input, select { width: 100%; padding: 8px 10px; font: inherit; color: var(--ink);
                background: var(--bg); border: 1px solid var(--line); border-radius: 4px; }
input:focus, select:focus, button:focus-visible, a:focus-visible { outline: 2px solid var(--accent); outline-offset: 1px; }
.login input { margin-bottom: 14px; }
.presets { grid-column: 1 / -1; display: flex; flex-wrap: wrap; gap: 8px; }
.presets button { background: transparent; color: var(--accent); border: 1px solid var(--line);
                  padding: 4px 10px; font-size: 13px; }
.actions { grid-column: 1 / -1; display: flex; gap: 10px; flex-wrap: wrap; }
button, a.btn { font: inherit; padding: 8px 16px; border-radius: 4px; border: 1px solid var(--accent);
         background: var(--accent); color: var(--accent-ink); cursor: pointer; text-decoration: none; display: inline-block; }
button.ghost, a.btn.ghost { background: transparent; color: var(--accent); }
.link { background: none; border: none; color: var(--muted); padding: 0; text-decoration: underline; }
.err { color: var(--err); margin: 0 0 14px; }
.note { color: var(--muted); font-size: 13px; margin: 12px 0 0; }
.daybar { display: flex; flex-wrap: wrap; gap: 10px; align-items: center; justify-content: space-between; margin-bottom: 16px; }
.daybar nav { display: flex; gap: 8px; flex-wrap: wrap; }
.tablewrap { overflow-x: auto; }
table { border-collapse: collapse; width: 100%; font-size: 14px; font-variant-numeric: tabular-nums; }
th, td { padding: 6px 10px; border-bottom: 1px solid var(--line); text-align: right; white-space: nowrap; }
th:first-child, td:first-child { text-align: left; }
th { font-weight: 600; color: var(--muted); position: sticky; top: 0; background: var(--panel); }
td.l { text-align: left; }
td.in { color: var(--in); } td.out { color: var(--out); }
td a { color: var(--accent); }
tr.total td { font-weight: 600; border-bottom: 2px solid var(--line); background: var(--bg); }
tr.empty td { color: var(--zero); }
table.totals { width: auto; margin-bottom: 16px; }
</style>
</head>
<body>
<main>
<?php if (!$logged): ?>
    <div class="panel login">
        <h1>Registro chiamate esterne</h1>
        <p class="sub">Accedi per consultare il registro.</p>
        <?php if ($error): ?><p class="err"><?= h($error) ?></p><?php endif; ?>
        <form method="post" action="<?= h(selfUrl()) ?>" autocomplete="off" style="margin-top:16px">
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
            <p class="sub">Chiamate effettuate verso numeri esterni e ricevute da numeri pubblici. Le chiamate tra interni sono escluse.</p>
        </div>
        <form method="post" action="<?= h(selfUrl()) ?>">
            <input type="hidden" name="action" value="logout">
            <input type="hidden" name="csrf" value="<?= h($_SESSION['csrf']) ?>">
            <button class="link" type="submit">Esci</button>
        </form>
    </header>

    <?php if ($view === 'day' && $calls !== null):
        $dPrev = (clone $dDay)->modify('-1 day')->format('Y-m-d');
        $dNext = (clone $dDay)->modify('+1 day')->format('Y-m-d');
    ?>
    <div class="panel">
        <div class="daybar">
            <h2>Chiamate di <?= h(dayLabel($fDay)) ?></h2>
            <nav>
                <a class="btn ghost" href="<?= h(selfUrl($range + ['view' => 'summary'])) ?>">Torna al riepilogo</a>
                <a class="btn ghost" href="<?= h(selfUrl($range + ['view' => 'day', 'day' => $dPrev])) ?>">Giorno precedente</a>
                <?php if ($dNext <= $today): ?>
                    <a class="btn ghost" href="<?= h(selfUrl($range + ['view' => 'day', 'day' => $dNext])) ?>">Giorno successivo</a>
                <?php endif; ?>
                <a class="btn" href="<?= h(selfUrl($range + ['view' => 'day', 'day' => $fDay, 'csv' => 'detail'])) ?>">Scarica CSV del giorno</a>
            </nav>
        </div>

        <?php $tb = totalsBlock($tot); ?>
        <table class="totals">
            <thead><tr><?php foreach ($tb[0] as $c): ?><th><?= h($c) ?></th><?php endforeach; ?></tr></thead>
            <tbody>
            <?php foreach (array_slice($tb, 1) as $i => $line): ?>
                <tr class="<?= $i === 2 ? 'total' : '' ?>"><?php foreach ($line as $j => $v): ?>
                    <td class="<?= $j === 0 ? ($i === 0 ? 'out' : ($i === 1 ? 'in' : '')) : '' ?>"><?= h($v) ?></td>
                <?php endforeach; ?></tr>
            <?php endforeach; ?>
            </tbody>
        </table>

        <?php if (!$calls): ?>
            <p class="note">Nessuna chiamata esterna in questo giorno.</p>
        <?php else: ?>
            <div class="tablewrap">
            <table>
                <thead><tr><?php foreach (detailHeader() as $i => $c): if ($i === 0) continue; ?><th><?= h($c) ?></th><?php endforeach; ?></tr></thead>
                <tbody>
                <?php foreach ($calls as $c): $line = detailLine($c); array_shift($line); ?>
                    <tr><?php foreach ($line as $i => $v):
                        $cls = '';
                        if ($i === 1) { $cls = $v === 'Ricevuta' ? 'in' : 'out'; }
                        if ($i >= 1 && $i <= 10) { $cls .= ' l'; }
                    ?><td class="<?= h(trim($cls)) ?>"><?= h($v) ?></td><?php endforeach; ?></tr>
                <?php endforeach; ?>
                </tbody>
            </table>
            </div>
            <p class="note"><?= count($calls) ?> chiamate esterne. I minuti si riferiscono alla sola conversazione.</p>
        <?php endif; ?>
    </div>

    <?php else: ?>
    <div class="panel">
        <?php if ($error): ?><p class="err"><?= h($error) ?></p><?php endif; ?>
        <form method="get" action="<?= h(selfUrl()) ?>" class="grid" id="f">
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
            <div class="actions">
                <button type="submit" name="view" value="summary">Mostra riepilogo</button>
                <button type="submit" name="csv" value="summary" class="ghost">Scarica CSV riepilogo</button>
                <button type="submit" name="csv" value="detail" class="ghost">Scarica CSV dettaglio periodo</button>
            </div>
        </form>
        <p class="note">I minuti si riferiscono alla sola conversazione delle chiamate risposte. Fai clic su un giorno per vedere l'elenco completo delle chiamate.</p>
    </div>

    <?php if ($view === 'summary' && $rows !== null): ?>
    <div class="panel">
        <div class="tablewrap">
        <table>
            <thead><tr><?php foreach (summaryHeader() as $c): ?><th><?= h($c) ?></th><?php endforeach; ?></tr></thead>
            <tbody>
                <tr class="total"><td>Totale periodo</td><?php foreach (summaryValues($tot) as $v): ?><td><?= h($v) ?></td><?php endforeach; ?></tr>
            <?php foreach ($rows as $day => $r): $n = $r['out_tot'] + $r['in_tot']; ?>
                <tr class="<?= $n ? '' : 'empty' ?>">
                    <td><?php if ($n): ?><a href="<?= h(selfUrl($range + ['view' => 'day', 'day' => $day])) ?>"><?= h(dayLabel($day)) ?></a><?php else: ?><?= h(dayLabel($day)) ?><?php endif; ?></td>
                    <?php foreach (summaryValues($r) as $v): ?><td><?= h($v) ?></td><?php endforeach; ?>
                </tr>
            <?php endforeach; ?>
            </tbody>
        </table>
        </div>
    </div>
    <?php endif; ?>
    <?php endif; ?>

<script>
(function () {
    var f = document.getElementById('from'), t = document.getElementById('to');
    if (!f || !t) { return; }
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
