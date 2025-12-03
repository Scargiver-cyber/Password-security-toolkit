"""
Secure Password Generator Module
Uses cryptographically secure methods to generate passwords and passphrases.
"""

import secrets
import string
from typing import List, Optional

# EFF's Large Wordlist for passphrases (subset for demo - full list has 7776 words)
WORDLIST = [
    "abandon", "ability", "able", "about", "above", "absent", "absorb", "abstract",
    "absurd", "abuse", "access", "accident", "account", "accuse", "achieve", "acid",
    "acoustic", "acquire", "across", "action", "actor", "actress", "actual", "adapt",
    "address", "adjust", "admit", "adult", "advance", "advice", "aerobic", "affair",
    "afford", "afraid", "again", "agent", "agree", "ahead", "airport", "aisle",
    "alarm", "album", "alcohol", "alert", "alien", "allow", "almost", "alone",
    "alpha", "already", "also", "alter", "always", "amateur", "amazing", "among",
    "amount", "amused", "analyst", "anchor", "ancient", "anger", "angle", "angry",
    "animal", "ankle", "announce", "annual", "another", "answer", "antenna", "antique",
    "anxiety", "apart", "apology", "appear", "apple", "approve", "april", "arch",
    "arctic", "arena", "argue", "armed", "armor", "army", "around", "arrange",
    "arrest", "arrive", "arrow", "artist", "artwork", "aspect", "assault", "asset",
    "assist", "assume", "asthma", "athlete", "atom", "attack", "attend", "attitude",
    "attract", "auction", "audit", "august", "aunt", "author", "auto", "autumn",
    "average", "avocado", "avoid", "awake", "aware", "away", "awesome", "awful",
    "awkward", "axis", "baby", "bachelor", "bacon", "badge", "balance", "balcony",
    "ball", "bamboo", "banana", "banner", "barrel", "basket", "battery", "beach",
    "beacon", "beauty", "because", "become", "bedroom", "before", "begin", "behave",
    "behind", "believe", "belong", "bench", "benefit", "best", "betray", "better",
    "between", "beyond", "bicycle", "billion", "biology", "bird", "birth", "bitter",
    "black", "blade", "blame", "blanket", "blast", "bleak", "bless", "blind",
    "blood", "blossom", "blouse", "blue", "blur", "blush", "board", "boat",
    "body", "boil", "bomb", "bonus", "book", "boost", "border", "boring",
    "borrow", "boss", "bottom", "bounce", "brain", "brand", "brass", "brave",
    "bread", "breeze", "brick", "bridge", "brief", "bright", "bring", "brisk",
    "broccoli", "broken", "bronze", "brother", "brown", "brush", "bubble", "bucket",
    "budget", "buffalo", "build", "bulb", "bulk", "bullet", "bundle", "bunker",
    "burden", "burger", "burst", "butter", "buyer", "cabbage", "cabin", "cable",
    "cactus", "cage", "cake", "call", "calm", "camera", "camp", "canal",
    "cancel", "candy", "cannon", "canoe", "canvas", "canyon", "capable", "capital",
    "captain", "carbon", "card", "cargo", "carpet", "carry", "cart", "case",
    "castle", "casual", "catalog", "catch", "category", "cattle", "caught", "cause",
    "caution", "cave", "ceiling", "celery", "cement", "census", "century", "cereal",
    "certain", "chair", "chalk", "champion", "change", "chaos", "chapter", "charge",
    "chase", "cheap", "check", "cheese", "chef", "cherry", "chest", "chicken",
    "chief", "child", "chimney", "choice", "choose", "chronic", "chuckle", "chunk",
    "churn", "cigar", "circle", "citizen", "city", "civil", "claim", "clap",
    "clarify", "claw", "clean", "clerk", "clever", "click", "client", "cliff",
    "climb", "clinic", "clock", "close", "cloth", "cloud", "clown", "club",
    "cluster", "coach", "coast", "coconut", "coffee", "coin", "collect", "color",
    "column", "combine", "comfort", "comic", "common", "company", "concert", "conduct",
    "confirm", "congress", "connect", "consider", "control", "convince", "cookie", "copper",
    "coral", "core", "corn", "correct", "cosmic", "costume", "cotton", "couch",
    "country", "couple", "course", "cousin", "cover", "coyote", "crack", "cradle",
    "craft", "crane", "crash", "crater", "crawl", "crazy", "cream", "credit",
    "creek", "crew", "cricket", "crime", "crisp", "critic", "crop", "cross",
    "crouch", "crowd", "crucial", "cruel", "cruise", "crumble", "crunch", "crush",
    "crystal", "cube", "culture", "curtain", "curve", "cushion", "custom", "cycle",
    "danger", "daring", "dash", "daughter", "dawn", "debate", "decade", "december",
    "decide", "decline", "decorate", "decrease", "deer", "defense", "define", "degree",
    "delay", "deliver", "demand", "denial", "dentist", "deny", "depart", "depend",
    "deposit", "depth", "deputy", "derive", "describe", "desert", "design", "desk",
    "despair", "destroy", "detail", "detect", "develop", "device", "devote", "diamond",
    "diary", "diesel", "differ", "digital", "dignity", "dilemma", "dinner", "dinosaur",
    "direct", "dirt", "disagree", "discover", "disease", "dish", "dismiss", "disorder",
    "display", "distance", "divert", "divide", "divorce", "dizzy", "doctor", "document",
    "dolphin", "domain", "donate", "donkey", "donor", "door", "dose", "double",
    "dragon", "drama", "drastic", "draw", "dream", "dress", "drift", "drill",
    "drink", "drip", "drive", "drop", "drum", "duck", "dumb", "dune",
    "during", "dust", "dutch", "dwarf", "dynamic", "eager", "eagle", "early",
    "earth", "easily", "east", "easy", "echo", "ecology", "economy", "edge",
    "effort", "eight", "either", "elbow", "elder", "electric", "elegant", "element",
    "elephant", "elevator", "elite", "else", "embark", "embody", "embrace", "emerge",
    "emotion", "employ", "empower", "empty", "enable", "enact", "endless", "endorse",
    "enemy", "energy", "enforce", "engage", "engine", "enhance", "enjoy", "enlist",
    "enough", "enrich", "enroll", "ensure", "enter", "entire", "entry", "envelope",
    "episode", "equal", "equip", "erosion", "error", "escape", "essay", "essence",
    "estate", "eternal", "ethics", "evidence", "evil", "evolve", "exact", "example",
    "excess", "exchange", "excite", "exclude", "excuse", "execute", "exercise", "exhaust",
    "exhibit", "exile", "exist", "exotic", "expand", "expect", "expire", "explain",
    "expose", "express", "extend", "extra", "extreme", "fabric", "face", "faculty",
    "fade", "faint", "faith", "false", "fame", "family", "famous", "fancy",
    "fantasy", "farm", "fashion", "father", "fatigue", "fault", "favorite", "feature",
    "february", "federal", "feel", "female", "fence", "festival", "fetch", "fever",
    "fiber", "fiction", "field", "figure", "filter", "final", "find", "finger",
    "finish", "fire", "firm", "fiscal", "fish", "fitness", "flag", "flame",
    "flash", "flavor", "flight", "flip", "float", "flock", "floor", "flower",
    "fluid", "flush", "focus", "follow", "food", "foot", "force", "forest",
    "forget", "fork", "fortune", "forum", "forward", "fossil", "foster", "found",
    "founder", "fragile", "frame", "frequent", "fresh", "friend", "fringe", "frog",
    "front", "frost", "frozen", "fruit", "fuel", "function", "funny", "furnace",
    "fury", "future", "gadget", "galaxy", "gallery", "game", "garage", "garbage",
    "garden", "garlic", "garment", "gather", "gauge", "gaze", "general", "genius",
    "genre", "gentle", "genuine", "gesture", "ghost", "giant", "gift", "giggle",
    "ginger", "giraffe", "glacier", "glad", "glance", "glare", "glass", "glide",
    "glimpse", "globe", "gloom", "glory", "glove", "glow", "glue", "goat",
    "goddess", "gold", "good", "goose", "gorilla", "gospel", "gossip", "govern",
    "grace", "grain", "grant", "grape", "grass", "gravity", "great", "green",
    "grid", "grief", "grit", "grocery", "ground", "group", "grow", "grunt",
    "guard", "guess", "guide", "guilt", "guitar", "gun", "gym", "habit",
    "hammer", "hand", "happy", "harbor", "hard", "harvest", "hawk", "hazard",
    "health", "heart", "heavy", "height", "hero", "hidden", "high", "hint",
    "history", "hobby", "hockey", "hold", "holiday", "hollow", "home", "honey",
    "honor", "hope", "horizon", "horn", "horror", "horse", "hospital", "host",
    "hotel", "hour", "hover", "huge", "human", "humble", "humor", "hundred",
    "hungry", "hunt", "hurdle", "hurry", "husband", "hybrid", "icon", "idea",
    "identify", "idle", "ignore", "illegal", "illness", "image", "imitate", "immense",
    "immune", "impact", "impose", "improve", "impulse", "inch", "include", "income",
    "increase", "index", "indicate", "indoor", "industry", "infant", "inflict", "inform",
    "inhale", "inherit", "initial", "inject", "injury", "inner", "innocent", "input",
    "inquiry", "insane", "insect", "inside", "inspire", "install", "intact", "interest",
    "interval", "into", "invest", "invite", "involve", "iron", "island", "isolate",
    "issue", "ivory", "jacket", "jaguar", "jealous", "jeans", "jelly", "jewel",
    "joke", "journey", "judge", "juice", "jump", "jungle", "junior", "junk",
    "justice", "kangaroo", "keen", "keep", "ketchup", "keyboard", "kick", "kidney",
    "kingdom", "kiss", "kitchen", "kite", "kitten", "kiwi", "knee", "knife",
    "knock", "know", "label", "labor", "ladder", "lake", "lamp", "language",
    "laptop", "large", "later", "latin", "laugh", "laundry", "lava", "lawn",
    "lawsuit", "layer", "leader", "leaf", "learn", "leather", "leave", "lecture",
    "left", "legal", "legend", "leisure", "lemon", "length", "lens", "leopard",
    "lesson", "letter", "level", "liberty", "library", "license", "life", "lift",
    "light", "limit", "link", "lion", "liquid", "list", "little", "live",
    "lizard", "load", "loan", "lobster", "local", "lock", "logic", "lonely",
    "long", "loop", "lottery", "loud", "lounge", "love", "loyal", "lucky",
    "luggage", "lumber", "lunar", "lunch", "luxury", "machine", "magic", "magnet",
    "maid", "mail", "major", "make", "mammal", "manage", "mandate", "mango",
    "mansion", "manual", "maple", "marble", "march", "margin", "marine", "market",
    "marriage", "mask", "mass", "master", "match", "material", "math", "matrix",
    "matter", "maximum", "meadow", "measure", "media", "melody", "member", "memory",
    "mention", "menu", "mercy", "merge", "merit", "message", "metal", "method",
    "middle", "midnight", "million", "mimic", "mind", "minimum", "minor", "minute",
    "miracle", "mirror", "misery", "mission", "mistake", "mixed", "mixture", "mobile",
    "model", "modify", "moment", "monitor", "monkey", "monster", "month", "moon",
    "moral", "morning", "mosquito", "mother", "motion", "motor", "mountain", "mouse",
    "movie", "much", "muffin", "multiply", "muscle", "museum", "mushroom", "music",
    "must", "mutual", "myself", "mystery", "myth", "naive", "name", "napkin",
    "narrow", "nasty", "nation", "nature", "near", "neck", "negative", "neglect",
    "neither", "nephew", "nerve", "nest", "network", "neutral", "never", "news",
    "night", "noble", "noise", "nominee", "normal", "north", "notable", "note",
    "nothing", "notice", "novel", "november", "nuclear", "number", "nurse", "object",
    "obtain", "obvious", "occur", "ocean", "october", "odor", "offer", "office",
    "often", "olive", "olympic", "omit", "once", "only", "open", "opera",
    "opinion", "oppose", "option", "orange", "orbit", "orchard", "order", "ordinary",
    "organ", "orient", "original", "orphan", "ostrich", "other", "outdoor", "outer",
    "output", "outside", "oval", "oven", "over", "owner", "oxygen", "oyster",
    "ozone", "pact", "paddle", "page", "pair", "palace", "palm", "panda",
    "panel", "panic", "panther", "paper", "parade", "parent", "park", "parrot",
    "party", "pass", "patch", "path", "patient", "patrol", "pattern", "pause",
    "payment", "peace", "peanut", "pear", "peasant", "pelican", "penalty", "pencil",
    "people", "pepper", "perfect", "permit", "person", "phone", "photo", "phrase",
    "physical", "piano", "picnic", "picture", "piece", "pilot", "pink", "pioneer",
    "pitch", "pizza", "place", "planet", "plastic", "plate", "play", "please",
    "pledge", "pluck", "plug", "plunge", "poem", "poet", "point", "polar",
    "police", "policy", "pond", "pony", "pool", "popular", "portion", "position",
    "possible", "post", "potato", "pottery", "poverty", "powder", "power", "practice",
    "praise", "predict", "prefer", "prepare", "present", "pretty", "prevent", "price",
    "pride", "primary", "print", "priority", "prison", "private", "prize", "problem",
    "process", "produce", "profit", "program", "project", "promote", "proof", "property",
    "prosper", "protect", "proud", "provide", "public", "pudding", "pull", "pulp",
    "pulse", "pumpkin", "punch", "pupil", "puppy", "purchase", "purple", "purpose",
    "purse", "push", "puzzle", "pyramid", "quality", "quantum", "quarter", "question",
    "quick", "quit", "quiz", "quote", "rabbit", "raccoon", "race", "rack",
    "radar", "radio", "rail", "rain", "raise", "rally", "ramp", "ranch",
    "random", "range", "rapid", "rare", "rate", "rather", "raven", "razor",
    "ready", "real", "reason", "rebel", "rebuild", "recall", "receive", "recipe",
    "record", "recycle", "reduce", "reflect", "reform", "refuse", "region", "regret",
    "regular", "reject", "relax", "release", "relief", "rely", "remain", "remember",
    "remind", "remove", "render", "renew", "rent", "reopen", "repair", "repeat",
    "replace", "report", "require", "rescue", "research", "resist", "resource", "response",
    "result", "retire", "retreat", "return", "reunion", "reveal", "review", "reward",
    "rhythm", "ribbon", "rice", "rich", "ride", "ridge", "rifle", "right",
    "rigid", "ring", "riot", "ripple", "risk", "ritual", "rival", "river",
    "road", "roast", "robot", "robust", "rocket", "romance", "roof", "rookie",
    "room", "rose", "rotate", "rough", "round", "route", "royal", "rubber",
    "rude", "rugby", "ruin", "rule", "run", "runway", "rural", "sadness",
    "safari", "salad", "salmon", "salon", "salt", "salute", "sample", "sand",
    "satisfy", "satoshi", "sauce", "sausage", "save", "scale", "scan", "scatter",
    "scene", "scheme", "school", "science", "scissors", "scorpion", "scout", "scrap",
    "screen", "script", "scrub", "search", "season", "seat", "second", "secret",
    "section", "security", "seed", "segment", "select", "sell", "seminar", "senior",
    "sense", "sentence", "series", "session", "settle", "setup", "seven", "shadow",
    "shaft", "shallow", "share", "shed", "shell", "sheriff", "shield", "shift",
    "shine", "ship", "shiver", "shock", "shoe", "shoot", "shop", "short",
    "shoulder", "shove", "shrimp", "shrug", "shuffle", "sibling", "sick", "side",
    "siege", "sight", "sign", "silent", "silk", "silly", "silver", "similar",
    "simple", "since", "sing", "siren", "sister", "situate", "size", "skate",
    "sketch", "skill", "skin", "skirt", "skull", "slab", "slam", "sleep",
    "slender", "slice", "slide", "slight", "slim", "slogan", "slow", "slush",
    "small", "smart", "smile", "smoke", "smooth", "snack", "snake", "snap",
    "sniff", "snow", "soap", "soccer", "social", "sock", "soda", "soft",
    "solar", "soldier", "solid", "solution", "solve", "someone", "song", "soon",
    "sorry", "sort", "soul", "sound", "soup", "source", "south", "space",
    "spare", "spatial", "spawn", "speak", "special", "speed", "spell", "spend",
    "sphere", "spice", "spider", "spike", "spin", "spirit", "split", "sponsor",
    "spoon", "sport", "spot", "spray", "spread", "spring", "square", "squeeze",
    "squirrel", "stable", "stadium", "staff", "stage", "stairs", "stamp", "stand",
    "start", "state", "stay", "steak", "steel", "stem", "step", "stick",
    "still", "sting", "stock", "stone", "stool", "story", "stove", "strategy",
    "street", "strike", "strong", "struggle", "student", "stuff", "stumble", "style",
    "subject", "submit", "subway", "success", "sudden", "suffer", "sugar", "suggest",
    "suit", "summer", "sun", "sunny", "sunset", "super", "supply", "supreme",
    "surface", "surge", "surprise", "surround", "survey", "suspect", "sustain", "swallow",
    "swamp", "swap", "swarm", "swear", "sweet", "swift", "swim", "swing",
    "switch", "sword", "symbol", "symptom", "syrup", "system", "table", "tackle",
    "tail", "talent", "talk", "tank", "tape", "target", "task", "taste",
    "tattoo", "taxi", "teach", "team", "tell", "tenant", "tennis", "tent",
    "term", "test", "text", "thank", "that", "theme", "theory", "there",
    "they", "thing", "thought", "three", "thrive", "throw", "thumb", "thunder",
    "ticket", "tide", "tiger", "tilt", "timber", "time", "tiny", "tired",
    "tissue", "title", "toast", "tobacco", "today", "toddler", "together", "toilet",
    "token", "tomato", "tomorrow", "tone", "tongue", "tonight", "tool", "tooth",
    "topic", "torch", "tornado", "tortoise", "total", "touch", "tough", "tour",
    "toward", "tower", "town", "track", "trade", "traffic", "tragic", "train",
    "transfer", "trap", "trash", "travel", "tray", "treat", "tree", "trend",
    "trial", "tribe", "trick", "trigger", "trim", "trip", "trophy", "trouble",
    "truck", "truly", "trumpet", "trust", "truth", "tube", "tuition", "tumble",
    "tuna", "tunnel", "turkey", "turn", "turtle", "twelve", "twenty", "twice",
    "twin", "twist", "type", "typical", "ugly", "umbrella", "unable", "unaware",
    "uncle", "uncover", "under", "unfair", "unfold", "unhappy", "uniform", "unique",
    "unit", "universe", "unknown", "unlock", "unusual", "unveil", "update", "upgrade",
    "uphold", "upon", "upper", "upset", "urban", "urge", "usage", "used",
    "useful", "useless", "usual", "utility", "vacant", "vacuum", "vague", "valid",
    "valley", "valve", "vanish", "vapor", "various", "vault", "vehicle", "velvet",
    "vendor", "venture", "venue", "verb", "verify", "version", "vessel", "veteran",
    "viable", "vibrant", "victory", "video", "view", "village", "vintage", "violin",
    "virtual", "virus", "visa", "visit", "visual", "vital", "vivid", "vocal",
    "voice", "volcano", "volume", "vote", "voyage", "wage", "wagon", "wait",
    "walk", "wall", "walnut", "wander", "want", "warfare", "warm", "warrior",
    "wash", "wasp", "waste", "water", "wave", "wealth", "weapon", "wear",
    "weather", "wedding", "weekend", "weird", "welcome", "west", "whale", "wheat",
    "wheel", "whisper", "wide", "width", "wife", "wild", "will", "window",
    "wine", "wing", "winner", "winter", "wire", "wisdom", "wise", "wish",
    "witness", "wolf", "woman", "wonder", "wood", "wool", "word", "work",
    "world", "worry", "worth", "wrap", "wreck", "wrestle", "wrist", "write",
    "wrong", "yard", "year", "yellow", "young", "youth", "zebra", "zero",
    "zone", "zoom"
]

# Ambiguous characters that can be confused
AMBIGUOUS_CHARS = "il1Lo0O"


class PasswordGenerator:
    """Generate cryptographically secure passwords and passphrases."""

    def __init__(
        self,
        length: int = 16,
        use_uppercase: bool = True,
        use_lowercase: bool = True,
        use_digits: bool = True,
        use_special: bool = True,
        exclude_ambiguous: bool = False,
        min_uppercase: int = 1,
        min_lowercase: int = 1,
        min_digits: int = 1,
        min_special: int = 1
    ):
        self.length = length
        self.use_uppercase = use_uppercase
        self.use_lowercase = use_lowercase
        self.use_digits = use_digits
        self.use_special = use_special
        self.exclude_ambiguous = exclude_ambiguous
        self.min_uppercase = min_uppercase if use_uppercase else 0
        self.min_lowercase = min_lowercase if use_lowercase else 0
        self.min_digits = min_digits if use_digits else 0
        self.min_special = min_special if use_special else 0

        self._build_charset()

    def _build_charset(self):
        """Build the character set based on options."""
        self.charset = ""

        if self.use_lowercase:
            chars = string.ascii_lowercase
            if self.exclude_ambiguous:
                chars = ''.join(c for c in chars if c not in AMBIGUOUS_CHARS)
            self.charset += chars
            self.lowercase_chars = chars
        else:
            self.lowercase_chars = ""

        if self.use_uppercase:
            chars = string.ascii_uppercase
            if self.exclude_ambiguous:
                chars = ''.join(c for c in chars if c not in AMBIGUOUS_CHARS)
            self.charset += chars
            self.uppercase_chars = chars
        else:
            self.uppercase_chars = ""

        if self.use_digits:
            chars = string.digits
            if self.exclude_ambiguous:
                chars = ''.join(c for c in chars if c not in AMBIGUOUS_CHARS)
            self.charset += chars
            self.digit_chars = chars
        else:
            self.digit_chars = ""

        if self.use_special:
            self.special_chars = "!@#$%^&*()_+-=[]{}|;:,.<>?"
            self.charset += self.special_chars
        else:
            self.special_chars = ""

    def generate(self) -> str:
        """Generate a single secure password."""
        if not self.charset:
            raise ValueError("No character types selected!")

        # Calculate minimum requirements
        min_required = (
            self.min_uppercase +
            self.min_lowercase +
            self.min_digits +
            self.min_special
        )

        if min_required > self.length:
            raise ValueError(
                f"Minimum character requirements ({min_required}) "
                f"exceed password length ({self.length})"
            )

        password_chars = []

        # Add minimum required characters
        if self.min_uppercase and self.uppercase_chars:
            password_chars.extend(
                secrets.choice(self.uppercase_chars)
                for _ in range(self.min_uppercase)
            )

        if self.min_lowercase and self.lowercase_chars:
            password_chars.extend(
                secrets.choice(self.lowercase_chars)
                for _ in range(self.min_lowercase)
            )

        if self.min_digits and self.digit_chars:
            password_chars.extend(
                secrets.choice(self.digit_chars)
                for _ in range(self.min_digits)
            )

        if self.min_special and self.special_chars:
            password_chars.extend(
                secrets.choice(self.special_chars)
                for _ in range(self.min_special)
            )

        # Fill remaining length with random characters
        remaining = self.length - len(password_chars)
        password_chars.extend(
            secrets.choice(self.charset)
            for _ in range(remaining)
        )

        # Shuffle to avoid predictable ordering
        secrets.SystemRandom().shuffle(password_chars)

        return ''.join(password_chars)

    def generate_multiple(self, count: int = 5) -> List[str]:
        """Generate multiple secure passwords."""
        return [self.generate() for _ in range(count)]


class PassphraseGenerator:
    """Generate memorable passphrases using random words."""

    def __init__(
        self,
        num_words: int = 4,
        separator: str = "-",
        capitalize: bool = True,
        include_number: bool = True,
        wordlist: Optional[List[str]] = None
    ):
        self.num_words = num_words
        self.separator = separator
        self.capitalize = capitalize
        self.include_number = include_number
        self.wordlist = wordlist or WORDLIST

    def generate(self) -> str:
        """Generate a single passphrase."""
        words = [
            secrets.choice(self.wordlist)
            for _ in range(self.num_words)
        ]

        if self.capitalize:
            words = [word.capitalize() for word in words]

        passphrase = self.separator.join(words)

        if self.include_number:
            passphrase += self.separator + str(secrets.randbelow(9000) + 1000)

        return passphrase

    def generate_multiple(self, count: int = 5) -> List[str]:
        """Generate multiple passphrases."""
        return [self.generate() for _ in range(count)]


def generate_pin(length: int = 4) -> str:
    """Generate a random PIN code."""
    return ''.join(str(secrets.randbelow(10)) for _ in range(length))


def generate_password(
    length: int = 16,
    use_uppercase: bool = True,
    use_lowercase: bool = True,
    use_digits: bool = True,
    use_special: bool = True,
    exclude_ambiguous: bool = False
) -> str:
    """Convenience function to generate a password."""
    generator = PasswordGenerator(
        length=length,
        use_uppercase=use_uppercase,
        use_lowercase=use_lowercase,
        use_digits=use_digits,
        use_special=use_special,
        exclude_ambiguous=exclude_ambiguous
    )
    return generator.generate()


def generate_passphrase(
    num_words: int = 4,
    separator: str = "-",
    capitalize: bool = True,
    include_number: bool = True
) -> str:
    """Convenience function to generate a passphrase."""
    generator = PassphraseGenerator(
        num_words=num_words,
        separator=separator,
        capitalize=capitalize,
        include_number=include_number
    )
    return generator.generate()
