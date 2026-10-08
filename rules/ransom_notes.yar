/*
 * YARA rules for detecting ransom-note language and known ransomware
 * extension/marker patterns in plaintext files.
 *
 * These are intentionally written as *behavioral/language* signatures,
 * not signatures of real malware samples - they match the kind of text
 * a ransom note contains (payment demands, decryption threats, crypto
 * wallet mentions), so the detector can flag notes from families it has
 * never seen before, not just ones on a keyword list.
 */

rule Generic_Ransom_Note_Language
{
    meta:
        description = "Generic ransom note phrasing: encryption + payment demand + threat"
        severity = "critical"

    strings:
        $encrypted1 = "your files have been encrypted" nocase
        $encrypted2 = "all your files are encrypted" nocase
        $encrypted3 = "files have been locked" nocase

        $payment1 = "bitcoin" nocase
        $payment2 = "btc wallet" nocase
        $payment3 = "send payment" nocase
        $payment4 = "pay the ransom" nocase
        $payment5 = "decryption key" nocase
        $payment6 = "private key" nocase

        $threat1 = "will be deleted" nocase
        $threat2 = "lost forever" nocase
        $threat3 = "do not attempt to decrypt" nocase
        $threat4 = "do not rename" nocase
        $threat5 = "hours" nocase

        $contact1 = "to decrypt" nocase
        $contact2 = "how to decrypt" nocase
        $contact3 = "restore your files" nocase

    condition:
        1 of ($encrypted*) and (1 of ($payment*) or 1 of ($threat*) or 1 of ($contact*))
}

rule Ransom_Note_Filename_Pattern
{
    meta:
        description = "Common ransom note filenames dropped alongside encrypted files"
        severity = "high"

    strings:
        $f1 = "README_DECRYPT" nocase
        $f2 = "HOW_TO_DECRYPT" nocase
        $f3 = "DECRYPT_INSTRUCTIONS" nocase
        $f4 = "RESTORE_FILES" nocase
        $f5 = "HELP_DECRYPT" nocase

    condition:
        any of them
}

rule Crypto_Wallet_Address
{
    meta:
        description = "Looks like a cryptocurrency wallet address embedded in text"
        severity = "medium"

    strings:
        // Bitcoin-like address pattern (loose - for note context, not validation)
        $btc = /\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b/
        // Monero-like address pattern (loose)
        $xmr = /\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b/

    condition:
        any of them
}
