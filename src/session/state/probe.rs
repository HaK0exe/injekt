use secrecy::SecretString;
use zeroize::Zeroize;

/// Second-order candidate (Option A passive, 0 requête extra).
///
/// Marqueur bénin injecté via le chemin existant (union / stacked) et
/// potentiellement persisté côté serveur. Aucun revisit automatique :
/// l'opérateur vérifie manuellement sur la 2e page. Le marqueur reste
/// `SecretString` + `Zeroize`, la trace ne garde que des hashes.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct StoredProbe {
    /// Clé param `name@location` (ex: `user@body`), déjà scrubbed à l'affichage.
    pub store_param: String,
    /// Marqueur bénin jetable (ex: `u<8hex>`), jamais loggé en clair.
    pub marker: SecretString,
    /// `sha256 hex` de l'URL de stockage, pas l'URL claire en trace.
    pub store_url_hash: String,
}

impl StoredProbe {
    #[must_use]
    pub fn new(
        store_param: impl Into<String>,
        marker: SecretString,
        store_url_hash: impl Into<String>,
    ) -> Self {
        Self {
            store_param: store_param.into(),
            marker,
            store_url_hash: store_url_hash.into(),
        }
    }
}

impl Zeroize for StoredProbe {
    fn zeroize(&mut self) {
        self.store_param.zeroize();
        // `SecretString` zeroizes on drop; explicit wipe via replace.
        self.marker = SecretString::from(String::new());
        self.store_url_hash.zeroize();
    }
}
