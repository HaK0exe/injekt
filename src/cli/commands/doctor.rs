#![deny(unsafe_code)]

//! C15 — `injekt doctor` : santé de la config **LOCALE** — jamais la cible,
//! jamais le réseau (OPSEC : 0 socket TCP, 0 fetch). Chaque check est une
//! fonction pure `fn check_*(…) -> CheckResult` (`level` + une seule ligne)
//! testée sans réseau ; les valeurs viennent des résolutions existantes
//! (`Cli::effective_*_with`, precedence CLI > env > config > profil >
//! défauts — logique jamais dupliquée) et des métadonnées fichier (existe +
//! lisible via `fs::metadata`, pas de read complet).
//!
//! Wiring : early-branch dans `main` AVANT l'init tracing et le banner
//! (stdout pur, pas de `SqlMapStyle`) — miroir du serveur MCP.
//!
//! Différence volontaire vs runtime : un `./injekt.toml` cassé est
//! silencieusement ignoré par `file_config::load` (warn + défauts) — le
//! doctor le remonte en `Fail` : tuer la classe d'erreurs de config
//! silencieuse est sa raison d'être.

use crate::cli::args::Cli;
use crate::cli::file_config::{FileConfig, candidate_paths};
use crate::cli::output::console::stdout_colors_enabled;
use crate::cli::profile::Profile;
use crate::session::scrubber::Scrubber;
use owo_colors::OwoColorize;
use std::path::PathBuf;
use std::process::ExitCode;

// ---------------------------------------------------------------------------
// Types de sortie
// ---------------------------------------------------------------------------

/// Verdict d'un check : `Ok` (vert), `Warn` (jaune, n'opère pas l'exit) ou
/// `Fail` (rouge — une seule variante bascule l'exit 1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CheckLevel {
    Ok,
    Warn,
    Fail,
}

/// Un check = un niveau + une ligne unique, préfixée par son nom
/// (`config: …`, `proxy: …`, `cadence: …`, `ingestion: …`).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct CheckResult {
    pub level: CheckLevel,
    pub line: String,
}

impl CheckResult {
    #[must_use]
    pub fn ok<T: Into<String>>(line: T) -> Self {
        Self {
            level: CheckLevel::Ok,
            line: line.into(),
        }
    }

    #[must_use]
    pub fn warn<T: Into<String>>(line: T) -> Self {
        Self {
            level: CheckLevel::Warn,
            line: line.into(),
        }
    }

    #[must_use]
    pub fn fail<T: Into<String>>(line: T) -> Self {
        Self {
            level: CheckLevel::Fail,
            line: line.into(),
        }
    }
}

fn profile_name(p: Profile) -> String {
    format!("{p:?}").to_ascii_lowercase()
}

// ---------------------------------------------------------------------------
// Check 1 — config : résolution du TOML via `file_config.rs` tel quel
// ---------------------------------------------------------------------------

/// Résolution du fichier config : même boucle de candidats que
/// `file_config::load` (le premier candidat *existant et lisible* arbitre).
/// Uniquement des IO fichier local — jamais la cible, jamais le réseau.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum ConfigResolution {
    /// Aucun candidat existant ; `explicit` rappelle le `--config` demandé
    /// (quand il est introuvable/illisible, la ligne le signale).
    Absent { explicit: Option<String> },
    /// Premier fichier trouvé, parse TOML OK.
    Found { path: PathBuf, cfg: FileConfig },
    /// Premier fichier trouvé mais parse KO — `error` reproduit le message
    /// `toml` (ligne/colonne) ; aucune re-parse maison.
    Broken { path: PathBuf, error: String },
}

fn resolve_config(explicit: Option<&str>) -> ConfigResolution {
    for path in candidate_paths(explicit) {
        let Ok(content) = std::fs::read_to_string(&path) else {
            continue;
        };
        return match FileConfig::parse(&content) {
            Ok(cfg) => ConfigResolution::Found { path, cfg },
            Err(error) => ConfigResolution::Broken { path, error },
        };
    }
    ConfigResolution::Absent {
        explicit: explicit.map(str::to_owned),
    }
}

/// Check 1 (pur) — fichier trouvé + parse OK ⇒ résumé une ligne (profil
/// effectif, threads), `Warn` si un preset fichier est inconnu (le runtime
/// l'ignore en silence) ; absent ⇒ `Warn` « défauts intégrés » ; TOML
/// cassé ⇒ `Fail` avec l'erreur (ligne/colonne) du parse `toml`.
#[must_use]
pub fn check_config(
    res: &ConfigResolution,
    active: Option<Profile>,
    threads: usize,
) -> CheckResult {
    match res {
        ConfigResolution::Absent { explicit: None } => CheckResult::warn(
            "config: aucun fichier config (--config · ./injekt.toml · \
             ~/.config/injekt/config.toml) — défauts intégrés actifs",
        ),
        ConfigResolution::Absent { explicit: Some(p) } => CheckResult::warn(format!(
            "config: --config {p} introuvable/illisible et aucun candidat \
             auto-découvert — défauts intégrés actifs",
        )),
        ConfigResolution::Broken { path, error } => CheckResult::fail(format!(
            "config: TOML invalide ({}) — {error}",
            path.display(),
        )),
        ConfigResolution::Found { path, cfg } => {
            let mut level = CheckLevel::Ok;
            let mut note = String::new();
            let file_p = cfg.file_profile();
            // Preset effectif (+ provenance) sans ré-implémenter la
            // precedence : CLI > fichier, miroir d'`active_profile` ; un
            // preset fichier inconnu est un cas `Warn` (le runtime
            // l'ignore en silence via `file_profile` → `None`).
            let profile_seg;
            if let Some(cli_p) = active {
                if let Some(p) = file_p {
                    if cli_p == p {
                        profile_seg = format!("profil {} (fichier)", profile_name(p));
                    } else {
                        let raw = cfg.profile.as_deref().unwrap_or("?");
                        profile_seg = format!(
                            "profil {} (CLI, écrase « {raw} » du fichier)",
                            profile_name(cli_p),
                        );
                    }
                } else if let Some(raw) = cfg.profile.as_deref() {
                    level = CheckLevel::Warn;
                    note = format!(
                        " · preset fichier {raw:?} inconnu — ignoré au runtime \
                         (quick|balanced|stealth|aggressive)",
                    );
                    profile_seg = format!(
                        "profil {} (CLI, écrase le preset fichier inconnu)",
                        profile_name(cli_p),
                    );
                } else {
                    profile_seg = format!("profil {} (CLI)", profile_name(cli_p));
                }
            } else if let Some(p) = file_p {
                profile_seg = format!("profil {} (fichier)", profile_name(p));
            } else if let Some(raw) = cfg.profile.as_deref() {
                level = CheckLevel::Warn;
                note = format!(
                    " · preset fichier {raw:?} inconnu — ignoré au runtime \
                     (quick|balanced|stealth|aggressive)",
                );
                profile_seg = "profil: aucun (défauts intégrés)".to_owned();
            } else {
                profile_seg = "profil: aucun (défauts intégrés)".to_owned();
            }
            CheckResult {
                level,
                line: format!(
                    "config: {} — {profile_seg}{note} · threads {threads}",
                    path.display(),
                ),
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Check 2 — proxy : parse + validation du schéma, AUCUNE connexion
// ---------------------------------------------------------------------------

/// Check 2 (pur) — valeur via la résolution CLI > env > config (appelant) ;
/// absent ⇒ `Warn` (exit direct, anonymisation opt-in) ; présent ⇒
/// `ProxyConfig::parse` (`socks5://` ⇒ `Fail` avec le message DNS-leak
/// existant de `ProxyError::DnsLeak`, jamais dupliqué ; `socks5h://` /
/// http(s) ⇒ `Ok`). Uniquement parse et schéma : aucune connexion testée.
#[must_use]
pub fn check_proxy(proxy: Option<&str>) -> CheckResult {
    let Some(url) = proxy else {
        return CheckResult::warn(
            "proxy: aucun — exit réseau direct (anonymisation opt-in : --proxy \
             socks5h://… ou clé proxy du TOML)",
        );
    };
    // La valeur peut porter `user:pass@` : userinfo TOUJOURS redirigé —
    // même sur les chemins `Ok` (`ProxyError::Invalid` est déjà scrubé
    // côté http::proxy).
    let shown = crate::http::proxy::redact_userinfo(url);
    match crate::http::proxy::ProxyConfig::parse(url) {
        Err(e) => {
            // `DnsLeak` n'écho pas la valeur : on l'ajoute (redirigée).
            let detail = match &e {
                crate::http::proxy::ProxyError::DnsLeak => {
                    format!("{e} [valeur: {shown}]")
                }
                _ => format!("{e}"),
            };
            CheckResult::fail(format!("proxy: refusé — {detail}"))
        }
        Ok(cfg) => {
            let kind = match cfg {
                crate::http::proxy::ProxyConfig::Http(_) => "HTTP(S)",
                crate::http::proxy::ProxyConfig::Socks5h(_) => "SOCKS5h (DNS distant)",
            };
            CheckResult::ok(format!(
                "proxy: {shown} ({kind}) — schéma socks5h/http valide, vérifié \
                 sans connexion (0 socket)",
            ))
        }
    }
}

// ---------------------------------------------------------------------------
// Check 3 — cohérence cadence (jitter vs rate-limit)
// ---------------------------------------------------------------------------

/// Parse `"mean_ms,std_ms"` avec la même tolérance que
/// `client_builder::jitter_from_str` (tokens non numériques filtrés,
/// exactement 2 retenus) ; σ est replié ≥ 1.0 comme au runtime
/// (`Jitter::next_delay_with_rng`) ; NaN/∞ refusés (le parse f64 les
/// accepterait sinon). `None` = invalide ⇒ défaut `"750,250"` au runtime.
#[must_use]
pub fn parse_jitter_pair(jitter: &str) -> Option<(f64, f64)> {
    let parts: Vec<f64> = jitter
        .split(',')
        .filter_map(|x| x.trim().parse().ok())
        .collect();
    match parts.as_slice() {
        [mean, std] if mean.is_finite() && std.is_finite() && *std >= 0.0 => {
            Some((*mean, std.max(1.0)))
        }
        _ => None,
    }
}

/// Format `f64` lisible : entier sans décimales, sinon 2 décimales
/// (`1.0 → "1"`, `2.5 → "2.5"`, `0.05 → "0.05"`).
fn fmt_rate(v: f64) -> String {
    if !v.is_finite() {
        return "0".to_owned();
    }
    let s = format!("{v:.2}");
    let trimmed = s.trim_end_matches('0').trim_end_matches('.');
    if trimmed.is_empty() {
        "0".to_owned()
    } else {
        trimmed.to_owned()
    }
}

/// Check 3 (pur) — règle figée (§3 du plan) : `1000/rate_limit ≥
/// jitter_mean − 2·jitter_std` ⇒ `Ok` ; sinon `Warn` chiffré « cadence plus
/// rapide que le jitter → pattern détectable » + correction proposée.
///
/// Neutralité déterministe : pas de `rate_limit` explicite **et** pas de
/// profil ⇒ check neutre (on ne redit rien) ; la ligne reprend quand même
/// les valeurs effectives, en signalant un jitter explicite (lequel n'est
/// pas une cadence — règle inchangée). `rate ≤ 0` ⇒ `Warn` (le runtime
/// clamp le limiter à 0.1 rps) ; jitter non parseable ⇒ `Warn` (le runtime
/// retombe sur le défaut floored `"750,250"`).
#[must_use]
pub fn check_cadence(
    rate: f64,
    rate_explicit: bool,
    jitter: &str,
    jitter_explicit: bool,
    profile: Option<Profile>,
) -> CheckResult {
    if !rate_explicit && profile.is_none() {
        let jitter_note = if jitter_explicit { " (explicite)" } else { "" };
        return CheckResult::ok(format!(
            "cadence: rien d'explicite, check neutre (rate {} rps · \
             jitter \"{jitter}\"{jitter_note})",
            fmt_rate(rate),
        ));
    }
    if rate <= 0.0 {
        return CheckResult::warn(format!(
            "cadence: rate_limit {} ≤ 0 — le runtime clampe le limiter à \
             0.1 rps (10s/req)",
            fmt_rate(rate),
        ));
    }
    let Some((mean, std)) = parse_jitter_pair(jitter) else {
        return CheckResult::warn(format!(
            "cadence: jitter \"{jitter}\" invalide (attendu \"mean_ms,std_ms\") — \
             défaut \"750,250\" utilisé au runtime",
        ));
    };
    let interval_ms = 1000.0 / rate;
    let floor_ms = mean - 2.0 * std;
    if interval_ms >= floor_ms {
        CheckResult::ok(format!(
            "cadence: {} rps ({interval_ms:.0}ms) ≥ plancher jitter 2σ \
             ({mean:.0}−2×{std:.0}={floor_ms:.0}ms) — cohérent (jitter \"{jitter}\")",
            fmt_rate(rate),
        ))
    } else {
        // Correction : le plus grand rate encore cohérent, borné par le bas
        // (`1000/rate ≥ floor` ⟺ `rate ≤ 1000/floor`) — arrondi par le bas
        // à 2 décimales pour rester strictement dans la borne.
        let suggested = (1000.0 / floor_ms * 100.0).floor() / 100.0;
        CheckResult::warn(format!(
            "cadence: {} rps ({interval_ms:.0}ms) < plancher jitter 2σ \
             ({mean:.0}−2×{std:.0}={floor_ms:.0}ms) — cadence plus rapide que \
             le jitter → pattern détectable ; correction : --rate-limit {} \
             (ou jitter plus court, ex. \"300,100\")",
            fmt_rate(rate),
            fmt_rate(suggested),
        ))
    }
}

// ---------------------------------------------------------------------------
// Check 4 — ingestion : métadonnées des sources (--bulk-file/--raw-file/…)
// ---------------------------------------------------------------------------

/// État d'un chemin de source, déduit de `fs::metadata` (existe + type) —
/// pas de read complet (C15 : stat lexical only, un dossier de centaines de
/// raws reste un `metadata`).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SourceState {
    /// Existe et est un fichier.
    File,
    /// Existe et est un dossier.
    Dir,
    /// `fs::metadata` → `NotFound`.
    Missing,
    /// `fs::metadata` a échoué autrement (permissions, → `Err(e)`).
    Unreadable(String),
    /// `--bulk-file -` = alias stdin (géré tel quel par `target::ingest`).
    Stdin,
}

/// Un chemin de source ingestion et son état statique.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct SourceItem {
    pub flag: &'static str,
    pub raw: String,
    pub expects_dir: bool,
    pub state: SourceState,
}

/// Collecte (IO fichier local only — toujours 0 socket) des sources
/// ingestion déclarées, dans l'ordre de `TargetOpts`.
#[must_use]
pub fn collect_ingestion_sources(cli: &Cli) -> Vec<SourceItem> {
    let specs: [(&str, &Option<String>, bool); 5] = [
        ("bulk-file", &cli.target_opts.bulk_file, false),
        ("raw-file", &cli.target_opts.raw_file, false),
        ("raw-dir", &cli.target_opts.raw_dir, true),
        ("openapi-file", &cli.target_opts.openapi_file, false),
        ("sitemap-file", &cli.target_opts.sitemap_file, false),
    ];
    let mut out = Vec::new();
    for (flag, value, expects_dir) in specs {
        let Some(raw) = value else { continue };
        let state = if flag == "bulk-file" && raw == "-" {
            SourceState::Stdin
        } else {
            match std::fs::metadata(raw) {
                Ok(md) if md.is_dir() => SourceState::Dir,
                Ok(_) => SourceState::File,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => SourceState::Missing,
                Err(e) => SourceState::Unreadable(e.to_string()),
            }
        };
        out.push(SourceItem {
            flag,
            raw: raw.clone(),
            expects_dir,
            state,
        });
    }
    out
}

/// Check 4 (pur) — tout chemin absent/illisible ⇒ `Fail` (le run échouerait
/// immédiatement à l'ingestion) ; type inversé (fichier ↔ dossier) ⇒ `Warn` ;
/// tout OK ⇒ résumé ; aucune source ⇒ OK neutre (usage scan direct).
#[must_use]
pub fn check_ingestion(items: &[SourceItem]) -> CheckResult {
    if items.is_empty() {
        return CheckResult::ok(
            "ingestion: aucune source (--bulk-file/--raw-file/--raw-dir/\
             --openapi-file/--sitemap-file) — usage scan direct --target",
        );
    }
    let mut hard = Vec::new();
    let mut soft = Vec::new();
    let mut good = Vec::new();
    for it in items {
        match &it.state {
            SourceState::Stdin => good.push(format!("--{} (stdin)", it.flag)),
            SourceState::File => {
                if it.expects_dir {
                    soft.push(format!(
                        "--{}={} : fichier (dossier attendu)",
                        it.flag, it.raw
                    ));
                } else {
                    good.push(format!("--{}={}", it.flag, it.raw));
                }
            }
            SourceState::Dir => {
                if it.expects_dir {
                    good.push(format!("--{}={}", it.flag, it.raw));
                } else {
                    soft.push(format!(
                        "--{}={} : dossier (fichier attendu)",
                        it.flag, it.raw
                    ));
                }
            }
            SourceState::Missing => {
                hard.push(format!("--{}={} : introuvable", it.flag, it.raw));
            }
            SourceState::Unreadable(e) => {
                hard.push(format!("--{}={} : illisible ({e})", it.flag, it.raw));
            }
        }
    }
    let total = items.len();
    if !hard.is_empty() {
        let healthy = total - hard.len();
        CheckResult::fail(format!(
            "ingestion: {healthy}/{total} sources OK — {}",
            hard.join(" · "),
        ))
    } else if !soft.is_empty() {
        CheckResult::warn(format!(
            "ingestion: type inattendu — {} (le run toucherait une source \
             du mauvais type)",
            soft.join(" · "),
        ))
    } else {
        CheckResult::ok(format!(
            "ingestion: {total}/{total} sources présentes et lisibles — {}",
            good.join(", "),
        ))
    }
}

// ---------------------------------------------------------------------------
// Entrée : rendu stdout pur + exit code
// ---------------------------------------------------------------------------

/// Symbole `✓ / ! / ✗` ; couleur selon `stdout_colors_enabled` (`NO_COLOR`,
/// `TERM=dumb`, `CLICOLOR=0`, stdout non-TTY désactivent — la convention
/// repo, pas d'équivalent `INJEKT_NO_COLOR` inventé).
fn symbol(level: CheckLevel, colors: bool) -> String {
    let raw = match level {
        CheckLevel::Ok => "✓",
        CheckLevel::Warn => "!",
        CheckLevel::Fail => "✗",
    };
    if colors {
        match level {
            CheckLevel::Ok => raw.green().bold().to_string(),
            CheckLevel::Warn => raw.yellow().bold().to_string(),
            CheckLevel::Fail => raw.red().bold().to_string(),
        }
    } else {
        raw.to_owned()
    }
}

/// Run des 4 checks (config locale only) — rendu `✓/!/✗` une ligne par
/// check, puis `ExitCode` : 0 sans `✗`, 1 avec (mapping `main`, comme
/// `NoTarget` → 2 pour l'usage). Toute sortie passe par le `Scrubber`
/// (mêmes règles que le reste du CLI ; `--no-redact` respecté comme
/// ailleurs — les lignes doctor n'écho jamais un proxy brut en premier
/// lieu : userinfo déjà redirigé côté `check_proxy`).
///
/// Aucune requête réseau, aucun fetch, aucune écriture disque ; le seul IO
/// est la lecture du TOML et les `metadata` de sources ingestion.
///
/// # Errors
/// Jamais en pratique aujourd'hui (les échecs IO sont convertis en `Fail`
/// dans les checks) — la signature `Result` permet le wiring early-branch
/// identique à `mcp::server::run_mcp` dans `main`.
#[allow(clippy::unused_async)] // cohérence du wiring early-branch (await) dans main
pub async fn run(cli: &Cli) -> anyhow::Result<ExitCode> {
    let snap = cli.resolve_snapshot();

    let config = check_config(
        &resolve_config(cli.config.as_deref()),
        snap.profile,
        cli.effective_threads_with(&snap),
    );
    let proxy = check_proxy(cli.effective_proxy_with(&snap).as_deref());
    // Explicitité : CLI/env (clap remplit les champs) ou clé du TOML — la
    // precedence effective est celle des helpers `*_with(&snap)`, jamais
    // ré-implémentée ici.
    let cadence = check_cadence(
        cli.effective_rate_limit_with(&snap),
        cli.http.rate_limit.is_some() || snap.file.rate_limit.is_some(),
        &cli.effective_jitter_with(&snap),
        cli.http.jitter.is_some() || snap.file.jitter.is_some(),
        snap.profile,
    );
    let ingestion = check_ingestion(&collect_ingestion_sources(cli));

    let checks = [config, proxy, cadence, ingestion];
    let colors = stdout_colors_enabled();
    let scrubber = Scrubber::new(cli.output_opts.no_redact);

    let title = "injekt doctor — vérifications de la config locale (0 requête, 0 socket)";
    if colors {
        println!("{}", title.bright_cyan().bold());
    } else {
        println!("{title}");
    }
    for c in &checks {
        println!("{} {}", symbol(c.level, colors), scrubber.scrub(&c.line));
    }

    let failed = checks.iter().any(|c| c.level == CheckLevel::Fail);
    Ok(if failed {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use clap::Parser as _;

    // ---- check_config -------------------------------------------------------

    #[test]
    fn config_absent_warns_defaults() {
        let r = check_config(&ConfigResolution::Absent { explicit: None }, None, 5);
        assert_eq!(r.level, CheckLevel::Warn);
        assert!(r.line.contains("aucun fichier config"), "{}", r.line);
        assert!(r.line.contains("défauts intégrés"), "{}", r.line);
    }

    #[test]
    fn config_explicit_absent_mentions_flag() {
        let r = check_config(
            &ConfigResolution::Absent {
                explicit: Some("/tmp/nowhere.toml".to_owned()),
            },
            None,
            5,
        );
        assert_eq!(r.level, CheckLevel::Warn);
        assert!(r.line.contains("--config /tmp/nowhere.toml"), "{}", r.line);
    }

    #[test]
    fn config_toml_broken_fails_with_parse_error() {
        let err = FileConfig::parse("threads = \"many\"\n").expect_err("erreur de type de clé");
        let r = check_config(
            &ConfigResolution::Broken {
                path: PathBuf::from("./injekt.toml"),
                error: err,
            },
            None,
            5,
        );
        assert_eq!(r.level, CheckLevel::Fail);
        assert!(r.line.contains("./injekt.toml"), "{}", r.line);
        // Le parse toml cite la position : « TOML parse error at line 1, … ».
        assert!(r.line.contains("TOML parse error"), "{}", r.line);
    }

    #[test]
    fn config_found_summarizes_profile_and_threads() {
        let cfg = FileConfig::parse("profile = \"stealth\"\nthreads = 2\n").unwrap();
        let r = check_config(
            &ConfigResolution::Found {
                path: PathBuf::from("./injekt.toml"),
                cfg,
            },
            Some(Profile::Stealth),
            2,
        );
        assert_eq!(r.level, CheckLevel::Ok);
        assert!(r.line.contains("./injekt.toml"), "{}", r.line);
        assert!(r.line.contains("profil stealth (fichier)"), "{}", r.line);
        assert!(r.line.contains("threads 2"), "{}", r.line);
    }

    #[test]
    fn config_unknown_profile_name_warns_silent_ignore() {
        let cfg = FileConfig {
            profile: Some("nouveau".to_owned()),
            ..FileConfig::default()
        };
        let r = check_config(
            &ConfigResolution::Found {
                path: PathBuf::from("./injekt.toml"),
                cfg,
            },
            None,
            5,
        );
        assert_eq!(r.level, CheckLevel::Warn);
        assert!(
            r.line.contains("preset fichier \"nouveau\" inconnu"),
            "{}",
            r.line
        );
        assert!(r.line.contains("ignoré au runtime"), "{}", r.line);
    }

    #[test]
    fn config_cli_profile_overrides_file_with_note() {
        let cfg = FileConfig::parse("profile = \"stealth\"").unwrap();
        let r = check_config(
            &ConfigResolution::Found {
                path: PathBuf::from("./injekt.toml"),
                cfg,
            },
            Some(Profile::Quick),
            5,
        );
        assert_eq!(r.level, CheckLevel::Ok);
        // Le preset effectif est celui de la CLI, avec la mention d'écrasement.
        assert!(
            r.line
                .contains("profil quick (CLI, écrase « stealth » du fichier)"),
            "{}",
            r.line
        );
        assert!(!r.line.contains("profil stealth (fichier)"), "{}", r.line);
    }

    #[test]
    fn config_no_profile_section_shows_builtin_default() {
        let cfg = FileConfig::parse("threads = 3\n").unwrap();
        let r = check_config(
            &ConfigResolution::Found {
                path: PathBuf::from("./injekt.toml"),
                cfg,
            },
            None,
            3,
        );
        assert_eq!(r.level, CheckLevel::Ok);
        assert!(
            r.line.contains("profil: aucun (défauts intégrés)"),
            "{}",
            r.line
        );
        assert!(r.line.contains("threads 3"), "{}", r.line);
    }

    #[test]
    fn resolve_config_explicit_broken_toml_becomes_broken() {
        let path =
            std::env::temp_dir().join(format!("injekt-doctor-broken-{}.toml", std::process::id()));
        std::fs::write(&path, "threads = \"many\"\n").unwrap();
        let explicit = path.to_string_lossy().to_string();
        let res = resolve_config(Some(&explicit));
        std::fs::remove_file(&path).unwrap();
        match res {
            ConfigResolution::Broken { path: found, error } => {
                assert_eq!(found, path);
                assert!(error.contains("TOML parse error"), "{error}");
            }
            other => panic!("attendu Broken, obtenu {other:?}"),
        }
    }

    #[test]
    fn resolve_config_explicit_valid_toml_becomes_found() {
        let path =
            std::env::temp_dir().join(format!("injekt-doctor-found-{}.toml", std::process::id()));
        std::fs::write(&path, "threads = 2\nproxy = \"http://127.0.0.1:8118\"\n").unwrap();
        let explicit = path.to_string_lossy().to_string();
        let res = resolve_config(Some(&explicit));
        std::fs::remove_file(&path).unwrap();
        match res {
            ConfigResolution::Found { path: found, cfg } => {
                assert_eq!(found, path);
                assert_eq!(cfg.threads, Some(2));
                assert_eq!(cfg.proxy.as_deref(), Some("http://127.0.0.1:8118"));
            }
            other => panic!("attendu Found, obtenu {other:?}"),
        }
    }

    // ---- check_proxy --------------------------------------------------------

    #[test]
    fn proxy_absent_warns_optin() {
        let r = check_proxy(None);
        assert_eq!(r.level, CheckLevel::Warn);
        assert!(r.line.contains("proxy: aucun"), "{}", r.line);
    }

    #[test]
    fn proxy_socks5_fails_with_dns_leak_message() {
        let r = check_proxy(Some("socks5://127.0.0.1:9050"));
        assert_eq!(r.level, CheckLevel::Fail);
        // Message EXACT de `ProxyError::DnsLeak` — jamais dupliqué.
        assert!(
            r.line
                .contains("socks5 without remote DNS (socks5://) leaks DNS — use socks5h://"),
            "{}",
            r.line
        );
        assert!(
            r.line.contains("[valeur: socks5://127.0.0.1:9050]"),
            "{}",
            r.line
        );
    }

    #[test]
    fn proxy_socks5h_ok_and_userinfo_redacted() {
        let r = check_proxy(Some("socks5h://user:secret123@127.0.0.1:9050"));
        assert_eq!(r.level, CheckLevel::Ok);
        assert!(r.line.contains("SOCKS5h"), "{}", r.line);
        assert!(
            r.line.contains("socks5h://[REDACTED]@127.0.0.1:9050"),
            "{}",
            r.line
        );
        // Aucun secret en clair dans la ligne de sortie.
        assert!(!r.line.contains("secret123"), "{}", r.line);
        assert!(!r.line.contains(":user@"), "{}", r.line);
    }

    #[test]
    fn proxy_http_ok() {
        let r = check_proxy(Some("http://127.0.0.1:8118"));
        assert_eq!(r.level, CheckLevel::Ok);
        assert!(r.line.contains("HTTP(S)"), "{}", r.line);
        assert!(r.line.contains("sans connexion"), "{}", r.line);
    }

    // ---- check_cadence --------------------------------------------------------

    #[test]
    fn cadence_incoherent_warns_with_numbers_and_fix() {
        // 10 rps → 100ms ; jitter «2000,500» → plancher 2σ = 1000ms.
        let r = check_cadence(10.0, true, "2000,500", true, None);
        assert_eq!(r.level, CheckLevel::Warn);
        assert!(r.line.contains("100ms"), "{}", r.line);
        assert!(r.line.contains("1000ms"), "{}", r.line);
        assert!(r.line.contains("pattern détectable"), "{}", r.line);
        // Correction chiffrée : rate max cohérent = 1000/1000 = 1.
        assert!(r.line.contains("--rate-limit 1"), "{}", r.line);
    }

    #[test]
    fn cadence_coherent_ok_at_boundary() {
        // rate 1 → 1000ms ≥ plancher 2σ 1000ms (borne incluse par la règle).
        let r = check_cadence(1.0, true, "2000,500", true, None);
        assert_eq!(r.level, CheckLevel::Ok);
        assert!(r.line.contains("≥"), "{}", r.line);
        assert!(r.line.contains("cohérent"), "{}", r.line);
    }

    #[test]
    fn cadence_neutral_when_nothing_explicit() {
        // Pas de rate explicite ET pas de profil ⇒ check neutre.
        let r = check_cadence(10.0, false, "750,250", false, None);
        assert_eq!(r.level, CheckLevel::Ok);
        assert!(r.line.contains("neutre"), "{}", r.line);
        assert!(!r.line.contains("--rate-limit"), "{}", r.line);
    }

    #[test]
    fn cadence_jitter_garbage_warns_default_fallback() {
        let r = check_cadence(10.0, true, "vite", true, None);
        assert_eq!(r.level, CheckLevel::Warn);
        assert!(r.line.contains("jitter \"vite\" invalide"), "{}", r.line);
        assert!(r.line.contains("750,250"), "{}", r.line);
    }

    #[test]
    fn cadence_profile_driven_incoherent_with_numbers() {
        // Profil stealth seul (valeurs effectives du preset) : 3 rps →
        // 333ms < 1200−2×400=400ms ⇒ Warn chiffré, règle figée (§3) sans
        // exception dédiée.
        let r = check_cadence(3.0, false, "1200,400", false, Some(Profile::Stealth));
        assert_eq!(r.level, CheckLevel::Warn);
        assert!(r.line.contains("333ms"), "{}", r.line);
        assert!(r.line.contains("400ms"), "{}", r.line);
        assert!(r.line.contains("pattern détectable"), "{}", r.line);
    }

    #[test]
    fn cadence_rate_zero_warns_runtime_clamp() {
        let r = check_cadence(0.0, true, "750,250", true, None);
        assert_eq!(r.level, CheckLevel::Warn);
        assert!(r.line.contains("0.1 rps"), "{}", r.line);
    }

    #[test]
    fn parse_jitter_pair_matches_jitter_from_str_leniency() {
        assert_eq!(parse_jitter_pair("2000,500"), Some((2000.0, 500.0)));
        assert_eq!(parse_jitter_pair("  2000 , 500 "), Some((2000.0, 500.0)));
        // Tokens non numériques filtrés comme au runtime `jitter_from_str`.
        assert_eq!(parse_jitter_pair("abc,750"), None);
        assert_eq!(parse_jitter_pair("750"), None);
        assert_eq!(parse_jitter_pair("nan,250"), None);
        assert_eq!(parse_jitter_pair("750,inf"), None);
    }

    // ---- check_ingestion ---------------------------------------------------------

    fn item(flag: &'static str, raw: &str, dir: bool, state: SourceState) -> SourceItem {
        SourceItem {
            flag,
            raw: raw.to_owned(),
            expects_dir: dir,
            state,
        }
    }

    #[test]
    fn ingestion_empty_ok_neutral() {
        let r = check_ingestion(&[]);
        assert_eq!(r.level, CheckLevel::Ok);
        assert!(r.line.contains("aucune source"), "{}", r.line);
    }

    #[test]
    fn ingestion_two_paths_one_missing_fails() {
        let r = check_ingestion(&[
            item("raw-file", "/tmp/req-burp.txt", false, SourceState::File),
            item(
                "bulk-file",
                "/tmp/not/there.txt",
                false,
                SourceState::Missing,
            ),
        ]);
        assert_eq!(r.level, CheckLevel::Fail);
        assert!(r.line.contains("1/2 sources OK"), "{}", r.line);
        assert!(
            r.line
                .contains("--bulk-file=/tmp/not/there.txt : introuvable"),
            "{}",
            r.line
        );
    }

    #[test]
    fn ingestion_type_mismatch_warns_but_does_not_fail() {
        let r = check_ingestion(&[item(
            "raw-dir",
            "/tmp/somewhere.txt",
            true,
            SourceState::File,
        )]);
        assert_eq!(r.level, CheckLevel::Warn);
        assert!(r.line.contains("fichier (dossier attendu)"), "{}", r.line);
    }

    #[test]
    fn ingestion_stdin_alias_is_fine() {
        let r = check_ingestion(&[
            item("bulk-file", "-", false, SourceState::Stdin),
            item("raw-file", "/tmp/x.txt", false, SourceState::File),
        ]);
        assert_eq!(r.level, CheckLevel::Ok);
        assert!(r.line.contains("--bulk-file (stdin)"), "{}", r.line);
        assert!(r.line.contains("2/2 sources"), "{}", r.line);
    }

    #[test]
    fn collect_ingestion_maps_metadata_only() {
        let stamp = format!("injekt-doctor-ingest-{}", std::process::id());
        let real = std::env::temp_dir().join(format!("{stamp}-real.txt"));
        let missing = std::env::temp_dir().join(format!("{stamp}-missing.txt"));
        std::fs::write(&real, "https://lab.example.test/?id=1\n").unwrap();
        let cli = Cli::try_parse_from([
            "injekt",
            "--raw-file",
            real.to_string_lossy().as_ref(),
            "--bulk-file",
            missing.to_string_lossy().as_ref(),
        ])
        .expect("cli parses");
        let items = collect_ingestion_sources(&cli);
        std::fs::remove_file(&real).unwrap();
        assert_eq!(items.len(), 2);
        assert_eq!(items[0].state, SourceState::Missing);
        assert_eq!(items[0].flag, "bulk-file");
        assert_eq!(items[1].state, SourceState::File);
        assert!(!items[1].expects_dir);
    }

    #[test]
    fn collect_ingestion_stdin_alias() {
        let cli = Cli::try_parse_from(["injekt", "--bulk-file", "-"]).expect("cli parses");
        let items = collect_ingestion_sources(&cli);
        assert_eq!(items[0].state, SourceState::Stdin);
    }

    // ---- rendu -------------------------------------------------------------

    #[test]
    fn symbol_plain_without_colors() {
        assert_eq!(symbol(CheckLevel::Ok, false), "✓");
        assert_eq!(symbol(CheckLevel::Warn, false), "!");
        assert_eq!(symbol(CheckLevel::Fail, false), "✗");
    }
}
