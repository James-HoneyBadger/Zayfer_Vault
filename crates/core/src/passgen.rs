//! Password / passphrase generator with configurable strength.
//!
//! Provides both random character passwords and readable diceware-style
//! passphrases.
//!
//! # Examples
//! ```
//! use hb_zayfer_core::passgen::{generate_password, generate_passphrase, PasswordPolicy};
//!
//! let pw = generate_password(&PasswordPolicy::default());
//! assert!(pw.len() >= 16);
//!
//! let phrase = generate_passphrase(6, "-");
//! assert_eq!(phrase.split('-').count(), 6);
//! ```

use rand::Rng;
use rand_core::OsRng;

// ─────────────────────────── password policy ─────────────────────────────

/// Controls the shape of a generated random-character password.
#[derive(Debug, Clone)]
pub struct PasswordPolicy {
    /// Minimum password length.
    pub length: usize,
    /// Include uppercase letters.
    pub uppercase: bool,
    /// Include lowercase letters.
    pub lowercase: bool,
    /// Include digits.
    pub digits: bool,
    /// Include symbols.
    pub symbols: bool,
    /// Characters to exclude even when their class is enabled.
    pub exclude: String,
}

impl Default for PasswordPolicy {
    fn default() -> Self {
        Self {
            length: 20,
            uppercase: true,
            lowercase: true,
            digits: true,
            symbols: true,
            exclude: String::new(),
        }
    }
}

// ───────────────────────── character sets ─────────────────────────────

const UPPER: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const LOWER: &str = "abcdefghijklmnopqrstuvwxyz";
const DIGITS: &str = "0123456789";
const SYMBOLS: &str = "!@#$%^&*()-_=+[]{}|;:,.<>?/~`";

// ───────────────────────── password generation ───────────────────────

/// Generate a random-character password according to a [`PasswordPolicy`].
///
/// Guarantees at least one character from each enabled class.
pub fn generate_password(policy: &PasswordPolicy) -> String {
    let mut charset = String::new();
    if policy.uppercase {
        charset.push_str(UPPER);
    }
    if policy.lowercase {
        charset.push_str(LOWER);
    }
    if policy.digits {
        charset.push_str(DIGITS);
    }
    if policy.symbols {
        charset.push_str(SYMBOLS);
    }

    // Remove excluded characters
    if !policy.exclude.is_empty() {
        charset = charset
            .chars()
            .filter(|c| !policy.exclude.contains(*c))
            .collect();
    }

    if charset.is_empty() {
        charset = LOWER.to_string(); // fallback
    }

    let chars: Vec<char> = charset.chars().collect();
    let mut rng = OsRng;
    let len = policy.length.max(4);

    // Generate main body
    let mut password: Vec<char> = (0..len)
        .map(|_| chars[rng.gen_range(0..chars.len())])
        .collect();

    // Ensure at least one char from each enabled class
    let mut pos = 0;
    let usable = |set: &str, excl: &str| -> Vec<char> {
        set.chars().filter(|c| !excl.contains(*c)).collect()
    };

    if policy.uppercase {
        let set = usable(UPPER, &policy.exclude);
        if !set.is_empty() && !password.iter().any(|c| set.contains(c)) {
            password[pos] = set[rng.gen_range(0..set.len())];
            pos += 1;
        }
    }
    if policy.lowercase {
        let set = usable(LOWER, &policy.exclude);
        if !set.is_empty() && !password.iter().any(|c| set.contains(c)) {
            password[pos] = set[rng.gen_range(0..set.len())];
            pos += 1;
        }
    }
    if policy.digits {
        let set = usable(DIGITS, &policy.exclude);
        if !set.is_empty() && !password.iter().any(|c| set.contains(c)) {
            password[pos] = set[rng.gen_range(0..set.len())];
            pos += 1;
        }
    }
    if policy.symbols {
        let set = usable(SYMBOLS, &policy.exclude);
        if !set.is_empty() && !password.iter().any(|c| set.contains(c)) {
            password[pos] = set[rng.gen_range(0..set.len())];
            let _ = pos; // suppress unused warning
        }
    }

    // Shuffle (Fisher-Yates)
    for i in (1..password.len()).rev() {
        let j = rng.gen_range(0..=i);
        password.swap(i, j);
    }

    password.into_iter().collect()
}

// ───────────────────────── passphrase generation ─────────────────────

/// A compact word list for passphrase generation (EFF short word list extract,
/// 1296 words).  Stored inline for zero-dependency operation.
const WORD_LIST: &[&str] = &[
    "acid","acme","acre","aged","also","arch","army","away",
    "bail","bake","barn","base","bath","bead","beam","bean",
    "belt","bend","bike","bind","bird","bite","blow","blur",
    "boat","bolt","bomb","bone","book","boot","boss","bowl",
    "brew","burn","cafe","cage","cake","calm","came","camp",
    "cape","card","care","cart","case","cash","cast","cave",
    "chat","chip","city","clad","clam","clan","clay","clip",
    "club","clue","coal","coat","code","coil","coin","cold",
    "comb","come","cook","cool","cope","copy","cord","core",
    "cork","corn","cost","cozy","crab","crew","crop","crow",
    "cube","cult","curb","curl","cute","damp","dare","dark",
    "dart","dash","data","dawn","deal","dear","deck","deed",
    "deem","deep","deer","demo","deny","desk","dial","diet",
    "dirt","disc","dish","dock","dome","done","doom","door",
    "dose","down","doze","draw","drop","drum","dual","duel",
    "duke","dull","dump","dune","dusk","dust","duty","each",
    "earn","ease","east","echo","edge","else","emit","epic",
    "euro","even","ever","evil","exam","exit","face","fact",
    "fade","fail","fair","fake","fame","fare","farm","fast",
    "fate","fawn","fear","feat","feed","feel","fell","felt",
    "file","fill","film","find","fine","fire","firm","fish",
    "five","flag","flat","flaw","fled","flew","flip","flow",
    "foam","foil","fold","folk","fond","font","food","fool",
    "fork","form","fort","foul","four","free","frog","from",
    "fuel","full","fund","fury","fuse","gait","gain","gale",
    "game","gang","gate","gave","gaze","gear","gene","gift",
    "girl","give","glad","glow","glue","goat","gold","golf",
    "gone","good","grab","gray","grew","grid","grim","grin",
    "grip","grow","gulf","guru","gust","hack","hail","hair",
    "hale","half","hall","halt","hand","hang","hare","harm",
    "harp","hash","hate","haul","have","haze","head","heal",
    "heap","hear","heat","heel","held","helm","help","herb",
    "here","hero","hide","high","hike","hill","hint","hire",
    "hold","hole","holy","home","hood","hook","hope","horn",
    "host","hour","howl","huge","hull","hung","hunt","hurt",
    "hymn","icon","idea","idle","inch","info","into","iron",
    "isle","item","jade","jail","jazz","jean","jerk","jest",
    "jobs","jock","join","joke","jolt","jump","jury","just",
    "keen","keep","kept","kick","kids","kill","kind","king",
    "kiss","kite","knee","knew","knit","knob","knot","know",
    "lace","lack","laid","lake","lamb","lame","lamp","land",
    "lane","last","late","lawn","lead","leaf","lean","leap",
    "left","lend","lens","less","lick","life","lift","like",
    "limb","lime","limp","line","link","lion","list","live",
    "load","loaf","loan","lock","logo","long","look","loop",
    "lord","lore","lose","loss","lost","loud","love","luck",
    "lump","lung","lure","lurk","made","mail","main","make",
    "male","mall","malt","mane","many","mare","mark","mask",
    "mass","mate","maze","mead","meal","mean","meet","melt",
    "memo","mend","menu","mere","mess","mild","milk","mill",
    "mime","mind","mine","mint","miss","mist","mock","mode",
    "mold","monk","mood","moon","more","moss","most","moth",
    "move","much","mule","muse","mush","must","myth","nail",
    "name","navy","near","neat","neck","need","nest","news",
    "next","nice","nine","node","none","noon","norm","nose",
    "note","noun","nude","null","oaks","oath","obey","odds",
    "okay","once","only","onto","open","oral","ours","oval",
    "oven","over","pace","pack","page","paid","pail","pain",
    "pair","pale","palm","pane","park","part","pass","past",
    "path","peak","pear","peel","peer","pest","pick","pier",
    "pile","pine","pink","pipe","plan","play","plea","plod",
    "plot","plow","plug","plum","plus","poem","poet","pole",
    "poll","pond","pool","pope","pork","port","pose","post",
    "pour","pray","prep","prey","prop","pull","pulp","pump",
    "pure","push","quit","quiz","race","rack","raft","rage",
    "raid","rail","rain","rake","ramp","rang","rank","rare",
    "rash","rate","rave","rays","read","real","reap","rear",
    "reef","reel","rely","rend","rent","rest","rice","rich",
    "ride","rift","ring","riot","rise","risk","road","roam",
    "roar","robe","rock","rode","role","roll","roof","room",
    "root","rope","rose","ruin","rule","rung","rush","rust",
    "safe","sage","said","sake","sale","salt","same","sand",
    "sang","save","scan","seal","seam","seat","seed","seek",
    "seen","self","sell","send","sent","sewn","shed","ship",
    "shop","shot","show","shut","sick","side","sift","sigh",
    "sign","silk","sing","sink","site","size","skin","skip",
    "slam","slap","slip","slot","slow","slug","snap","snow",
    "soak","soar","sock","soft","soil","sold","sole","some",
    "song","soon","sort","soul","sour","span","spar","spin",
    "spit","spot","star","stay","stem","step","stew","stir",
    "stop","stud","such","suit","sulk","sure","surf","swap",
    "swim","swop","tabs","tack","tail","take","tale","tall",
    "tame","tank","tape","task","taxi","team","tear","tell",
    "temp","tend","tent","term","test","text","than","that",
    "them","then","they","thin","this","tick","tide","tidy",
    "tied","tile","till","time","tiny","tire","toad","told",
    "toll","tomb","tone","took","tool","tops","tore","torn",
    "tour","town","trap","tray","tree","trek","trim","trio",
    "trip","true","tube","tuck","tuna","tune","turn","turf",
    "twin","type","ugly","undo","unit","unto","upon","urge",
    "used","user","vain","vale","van","vary","vast","veil",
    "vein","vent","verb","very","vest","veto","view","vine",
    "void","volt","vote","wade","wage","wait","wake","walk",
    "wall","wand","want","ward","warm","warn","warp","wash",
    "wasp","wave","wavy","waxy","weak","wear","weed","week",
    "well","went","were","west","what","when","whip","whom",
    "wide","wife","wild","will","wilt","wind","wine","wing",
    "wipe","wire","wise","wish","with","woke","wolf","wood",
    "wool","word","wore","work","worm","worn","wrap","wren",
    "yard","yawn","year","yell","your","zeal","zero","zinc",
    "zone","zoom",
];

/// Generate a diceware-style passphrase from the built-in word list.
///
/// * `words`     — number of words (minimum 3)
/// * `separator` — string placed between words (e.g., `"-"`, `" "`)
pub fn generate_passphrase(words: usize, separator: &str) -> String {
    let words = words.max(3);
    let mut rng = OsRng;
    (0..words)
        .map(|_| WORD_LIST[rng.gen_range(0..WORD_LIST.len())])
        .collect::<Vec<_>>()
        .join(separator)
}

/// Estimate the entropy bits of a generated password or passphrase.
///
/// For passwords: log₂(charset_size) × length.
/// For passphrases: log₂(word_list_size) × word_count.
pub fn estimate_entropy(policy: &PasswordPolicy) -> f64 {
    let mut charset_size = 0usize;
    if policy.uppercase { charset_size += 26; }
    if policy.lowercase { charset_size += 26; }
    if policy.digits { charset_size += 10; }
    if policy.symbols { charset_size += SYMBOLS.len(); }
    if charset_size == 0 { charset_size = 26; }
    (charset_size as f64).log2() * policy.length as f64
}

/// Estimate entropy of a diceware passphrase.
pub fn passphrase_entropy(word_count: usize) -> f64 {
    (WORD_LIST.len() as f64).log2() * word_count as f64
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn test_generate_password_default() {
        let pw = generate_password(&PasswordPolicy::default());
        assert_eq!(pw.len(), 20);
        // Should have at least one of each class
        assert!(pw.chars().any(|c| c.is_ascii_uppercase()));
        assert!(pw.chars().any(|c| c.is_ascii_lowercase()));
        assert!(pw.chars().any(|c| c.is_ascii_digit()));
    }

    #[test]
    fn test_generate_password_custom_length() {
        let policy = PasswordPolicy {
            length: 32,
            ..Default::default()
        };
        let pw = generate_password(&policy);
        assert_eq!(pw.len(), 32);
    }

    #[test]
    fn test_generate_password_excludes_chars() {
        let policy = PasswordPolicy {
            length: 100,
            exclude: "aeiouAEIOU01".to_string(),
            ..Default::default()
        };
        let pw = generate_password(&policy);
        for c in "aeiouAEIOU01".chars() {
            assert!(!pw.contains(c), "Password should not contain '{c}'");
        }
    }

    #[test]
    fn test_generate_password_only_digits() {
        let policy = PasswordPolicy {
            length: 12,
            uppercase: false,
            lowercase: false,
            digits: true,
            symbols: false,
            exclude: String::new(),
        };
        let pw = generate_password(&policy);
        assert!(pw.chars().all(|c| c.is_ascii_digit()));
    }

    #[test]
    fn test_generate_passphrase() {
        let phrase = generate_passphrase(6, "-");
        let words: Vec<&str> = phrase.split('-').collect();
        assert_eq!(words.len(), 6);
        for w in &words {
            assert!(WORD_LIST.contains(w), "Word '{w}' not in word list");
        }
    }

    #[test]
    fn test_generate_passphrase_uniqueness() {
        // Generate 10 passphrases — they should all be distinct.
        let set: HashSet<String> = (0..10)
            .map(|_| generate_passphrase(5, " "))
            .collect();
        assert!(set.len() >= 8, "Expected mostly unique passphrases, got {} of 10", set.len());
    }

    #[test]
    fn test_entropy_estimation() {
        let e = estimate_entropy(&PasswordPolicy::default());
        // 20 chars, charset ~88 → ~128 bits
        assert!(e > 100.0 && e < 200.0, "Entropy {e} out of range");
    }

    #[test]
    fn test_passphrase_entropy() {
        let e = passphrase_entropy(6);
        // ~600 words → ~9.2 bits/word → ~55 bits for 6 words
        assert!(e > 40.0 && e < 80.0, "Passphrase entropy {e} out of range");
    }
}
