use super::types::{ParseLlmError, SuggestedPair};

// ── parsing commun ───────────────────────────────────────────────────

/// Extrait le premier segment JSON du texte (bloc fencé ou prose avec
/// tableau/objet) puis valide le schéma : liste non vide de paires
/// `true`/`false` non vides, tronquée à `max_pairs` (au moins 1).
pub(super) fn parse_pairs_loose(
    text: &str,
    max_pairs: u8,
) -> Result<Vec<SuggestedPair>, ParseLlmError> {
    let json = extract_json(text).ok_or(ParseLlmError::InvalidJson)?;
    let mut pairs: Vec<SuggestedPair> =
        serde_json::from_str(&json).map_err(|_| ParseLlmError::BadSchema)?;
    if pairs.is_empty() {
        return Err(ParseLlmError::BadSchema);
    }
    // Branches vides = hors-contrat (le validator les rejetterait de toute
    // façon, mais on échoue tôt sans requête cible).
    pairs.retain(|p| !p.true_branch.trim().is_empty() && !p.false_branch.trim().is_empty());
    if pairs.is_empty() {
        return Err(ParseLlmError::BadSchema);
    }
    let cap = usize::from(max_pairs.max(1));
    pairs.truncate(cap);
    Ok(pairs)
}

/// Extrait le premier segment JSON (`[`…`]` ou `{`…`}`) du texte.
/// Supporte les fences ```json … ```. `None` si introuvable.
pub(super) fn extract_json(text: &str) -> Option<String> {
    let t = text.trim();
    // Fence ```json … ``` ou ``` … ``` : prend le contenu du premier bloc.
    if let Some(start) = t.find("```") {
        let after_open = &t[start + 3..];
        let fence_end = after_open.find('\n').map_or(0, |i| i + 1);
        let inner = &after_open[fence_end..];
        if let Some(close) = inner.find("```") {
            let candidate = inner[..close].trim();
            if candidate.starts_with('[') || candidate.starts_with('{') {
                return Some(candidate.to_owned());
            }
        }
    }
    // premier `[`… dernier `]` (tableau), sinon premier `{`… dernier `}`.
    if let (Some(s), Some(e)) = (t.find('['), t.rfind(']'))
        && s < e
    {
        return Some(t[s..=e].to_owned());
    }
    if let (Some(s), Some(e)) = (t.find('{'), t.rfind('}'))
        && s < e
    {
        // Objet unique → enveloppe en liste pour le schéma commun.
        return Some(format!("[{}]", &t[s..=e]));
    }
    None
}
